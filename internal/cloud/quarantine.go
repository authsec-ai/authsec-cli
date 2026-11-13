package cloud

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/smithy-go"
)

// The inline policy that quarantines an AWS agent. No other policy of the
// role is ever read, changed or removed.
const (
	quarantinePolicy   = "AuthSecQuarantine"
	quarantineDocument = `{"Version":"2012-10-17","Statement":[{"Sid":"AuthSecQuarantine","Effect":"Deny","Action":"*","Resource":"*"}]}`
)

// Plan is a cloud change, shown before it is made.
type Plan struct {
	Agent          Agent
	Actions        []string // human readable
	PolicyName     string
	PolicyDocument string
	Applied        bool
}

// role is an IAM role named by its ARN.
type role struct {
	ARN, Account, Name string
}

// parseRole reads arn:<partition>:iam::<account>:role/<path/>name.
func parseRole(arn string) (role, error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" || parts[4] == "" || !strings.HasPrefix(parts[5], "role/") {
		return role{}, errors.New("not an IAM role ARN")
	}
	name := lastSegment(parts[5])
	if name == "" {
		return role{}, errors.New("not an IAM role ARN")
	}
	return role{ARN: arn, Account: parts[4], Name: name}, nil
}

// agentRole returns the execution role of an AWS agent, or why there is
// none.
func agentRole(a Agent) (role, error) {
	if a.Cloud != "aws" {
		return role{}, fmt.Errorf("agent %s is not an AWS agent", a.ID)
	}
	if a.Identity == "" {
		return role{}, fmt.Errorf("agent %s has no execution role ARN: nothing to quarantine", a.ID)
	}
	r, err := parseRole(a.Identity)
	if err != nil {
		return role{}, fmt.Errorf("agent %s: %s: %w", a.ID, a.Identity, err)
	}
	return r, nil
}

// QuarantineAWS puts an inline policy named AuthSecQuarantine, denying every
// action, on the agent's execution role. It only plans unless apply is set.
// It refuses an agent without a role ARN, and credentials for an account
// other than the role's.
func QuarantineAWS(ctx context.Context, c AWS, a Agent, apply bool) (Plan, error) {
	r, err := agentRole(a)
	if err != nil {
		return Plan{Agent: a}, err
	}
	p := Plan{
		Agent:          a,
		PolicyName:     quarantinePolicy,
		PolicyDocument: quarantineDocument,
		Actions: []string{
			fmt.Sprintf("put inline policy %s on role %s in account %s: deny every action on every resource", quarantinePolicy, r.Name, r.Account),
			"leave every other policy of the role unchanged",
		},
	}
	if !apply {
		return p, nil
	}
	cl, err := iamFor(ctx, c, a, r)
	if err != nil {
		return p, err
	}
	_, err = cl.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
		RoleName:       aws.String(r.Name),
		PolicyName:     aws.String(quarantinePolicy),
		PolicyDocument: aws.String(quarantineDocument),
	})
	if err != nil {
		return p, awsErr("global", "iam:PutRolePolicy "+r.Name, err)
	}
	p.Applied = true
	return p, nil
}

// ReleaseAWS deletes the AuthSecQuarantine inline policy from the agent's
// execution role, and nothing else. It only plans unless apply is set.
func ReleaseAWS(ctx context.Context, c AWS, a Agent, apply bool) (Plan, error) {
	r, err := agentRole(a)
	if err != nil {
		return Plan{Agent: a}, err
	}
	p := Plan{
		Agent:      a,
		PolicyName: quarantinePolicy,
		Actions: []string{
			fmt.Sprintf("delete inline policy %s from role %s in account %s", quarantinePolicy, r.Name, r.Account),
			"leave every other policy of the role unchanged",
		},
	}
	if !apply {
		return p, nil
	}
	cl, err := iamFor(ctx, c, a, r)
	if err != nil {
		return p, err
	}
	_, err = cl.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{
		RoleName:   aws.String(r.Name),
		PolicyName: aws.String(quarantinePolicy),
	})
	var api smithy.APIError
	if errors.As(err, &api) && api.ErrorCode() == "NoSuchEntity" {
		p.Actions = append(p.Actions, "the role had no "+quarantinePolicy+" policy: nothing removed")
		err = nil
	}
	if err != nil {
		return p, awsErr("global", "iam:DeleteRolePolicy "+r.Name, err)
	}
	p.Applied = true
	return p, nil
}

// iamFor returns an IAM client for the role's account. It refuses
// credentials for another account: a role of the same name there would be
// changed instead.
func iamFor(ctx context.Context, c AWS, a Agent, r role) (*iam.Client, error) {
	region := a.Region
	if region == "" && len(c.Regions) > 0 {
		region = c.Regions[0]
	}
	cfg, err := loadAWS(ctx, c.Profile, region)
	if err != nil {
		return nil, err
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	who, err := whoAmI(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if who.Account != r.Account {
		return nil, fmt.Errorf("aws: role %s is in account %s but the credentials are for account %s: use a profile for %s",
			r.Name, r.Account, who.Account, r.Account)
	}
	return iam.NewFromConfig(cfg), nil
}
