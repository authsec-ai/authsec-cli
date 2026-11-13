package cloud

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagent"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrockagent/types"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// maxAWSPages bounds every AWS list.
const maxAWSPages = 100

// loadAWS loads the SDK configuration: the named profile (or the default
// chain, which reads the environment) in region.
func loadAWS(ctx context.Context, profile, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{config.WithHTTPClient(httpClient)}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws: load configuration: %w", err)
	}
	if awsEndpoint != "" {
		cfg.BaseEndpoint = aws.String(awsEndpoint)
	}
	return cfg, nil
}

// caller is who the credentials belong to.
type caller struct {
	Account   string
	Partition string
}

// whoAmI calls sts:GetCallerIdentity, which needs no permission.
func whoAmI(ctx context.Context, cfg aws.Config) (caller, error) {
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return caller{}, awsErr(cfg.Region, "sts:GetCallerIdentity", err)
	}
	c := caller{Account: aws.ToString(out.Account), Partition: "aws"}
	if parts := strings.Split(aws.ToString(out.Arn), ":"); len(parts) > 1 && parts[1] != "" {
		c.Partition = parts[1]
	}
	return c, nil
}

// DiscoverAWS lists the Bedrock agents and AgentCore runtimes in every
// listed region (the profile's region when none are). An error in one
// region is collected and the other regions are still read.
func DiscoverAWS(ctx context.Context, c AWS) ([]Agent, []error) {
	regions := c.Regions
	first := ""
	if len(regions) > 0 {
		first = regions[0]
	}
	base, err := loadAWS(ctx, c.Profile, first)
	if err != nil {
		return nil, []error{err}
	}
	if len(regions) == 0 {
		if base.Region == "" {
			return nil, []error{errors.New("aws: no region: set AWS_REGIONS")}
		}
		regions = []string{base.Region}
	}
	who, err := whoAmI(ctx, base)
	if err != nil {
		return nil, []error{err}
	}
	var agents []Agent
	var errs []error
	for _, region := range regions {
		cfg := base.Copy()
		cfg.Region = region
		a, e := bedrockAgents(ctx, bedrockagent.NewFromConfig(cfg), region, who)
		agents, errs = append(agents, a...), append(errs, e...)
		a, e = agentCoreRuntimes(ctx, bedrockagentcorecontrol.NewFromConfig(cfg), region, who)
		agents, errs = append(agents, a...), append(errs, e...)
	}
	sortAgents(agents)
	return agents, errs
}

// bedrockAgents lists the Bedrock agents of one region. GetAgent is needed
// for each: the list carries no role or model. Instructions are never read.
func bedrockAgents(ctx context.Context, cl *bedrockagent.Client, region string, who caller) ([]Agent, []error) {
	var out []Agent
	var errs []error
	p := bedrockagent.NewListAgentsPaginator(cl, &bedrockagent.ListAgentsInput{})
	for page := 0; p.HasMorePages() && page < maxAWSPages; page++ {
		resp, err := p.NextPage(ctx)
		if err != nil {
			return out, append(errs, awsErr(region, "bedrock:ListAgents", err))
		}
		for _, s := range resp.AgentSummaries {
			a, err := bedrockAgent(ctx, cl, region, who, s)
			if err != nil {
				errs = append(errs, err)
			}
			out = append(out, a)
		}
	}
	return out, errs
}

// bedrockAgent builds one agent from its summary and GetAgent. A failed
// GetAgent keeps the agent (it was listed) with its role unknown.
func bedrockAgent(ctx context.Context, cl *bedrockagent.Client, region string, who caller, s bedrocktypes.AgentSummary) (Agent, error) {
	id := aws.ToString(s.AgentId)
	a := Agent{
		Cloud:    "aws",
		Kind:     kindBedrockAgent,
		ID:       fmt.Sprintf("arn:%s:bedrock:%s:%s:agent/%s", who.Partition, region, who.Account, id),
		Name:     aws.ToString(s.AgentName),
		Region:   region,
		Account:  who.Account,
		Status:   string(s.AgentStatus),
		Updated:  aws.ToTime(s.UpdatedAt),
		Console:  awsConsole(who.Partition, region, "bedrock", "/agents/"+id),
		Evidence: []string{"listed by bedrock:ListAgents in " + region},
	}
	d, err := cl.GetAgent(ctx, &bedrockagent.GetAgentInput{AgentId: aws.String(id)})
	if err == nil && d.Agent == nil {
		err = errors.New("no agent in the response")
	}
	if err != nil {
		e := awsErr(region, "bedrock:GetAgent "+id, err)
		a.Evidence = append(a.Evidence, "bedrock:GetAgent failed ("+errCode(err)+"): execution role unknown")
		return a, e
	}
	g := d.Agent
	if arn := aws.ToString(g.AgentArn); arn != "" {
		a.ID = arn
	}
	a.Identity = aws.ToString(g.AgentResourceRoleArn)
	a.Model = aws.ToString(g.FoundationModel)
	if g.AgentStatus != "" {
		a.Status = string(g.AgentStatus)
	}
	if g.UpdatedAt != nil {
		a.Updated = *g.UpdatedAt
	}
	a.Evidence = append(a.Evidence, "execution role and model from bedrock:GetAgent")
	return a, nil
}

// agentCoreRuntimes lists the AgentCore runtimes of one region, with
// GetAgentRuntime for each runtime's role.
func agentCoreRuntimes(ctx context.Context, cl *bedrockagentcorecontrol.Client, region string, who caller) ([]Agent, []error) {
	var out []Agent
	var errs []error
	p := bedrockagentcorecontrol.NewListAgentRuntimesPaginator(cl, &bedrockagentcorecontrol.ListAgentRuntimesInput{})
	for page := 0; p.HasMorePages() && page < maxAWSPages; page++ {
		resp, err := p.NextPage(ctx)
		if err != nil {
			return out, append(errs, awsErr(region, "bedrock-agentcore:ListAgentRuntimes", err))
		}
		for _, r := range resp.AgentRuntimes {
			id := aws.ToString(r.AgentRuntimeId)
			a := Agent{
				Cloud:    "aws",
				Kind:     kindAgentCoreRuntime,
				ID:       aws.ToString(r.AgentRuntimeArn),
				Name:     aws.ToString(r.AgentRuntimeName),
				Region:   region,
				Account:  who.Account,
				Status:   string(r.Status),
				Updated:  aws.ToTime(r.LastUpdatedAt),
				Console:  awsConsole(who.Partition, region, "bedrock-agentcore", "/agents/"+id),
				Evidence: []string{"listed by bedrock-agentcore:ListAgentRuntimes in " + region},
			}
			if a.ID == "" {
				a.ID = fmt.Sprintf("arn:%s:bedrock-agentcore:%s:%s:runtime/%s", who.Partition, region, who.Account, id)
			}
			if err := runtimeDetail(ctx, cl, region, id, &a); err != nil {
				errs = append(errs, err)
			}
			out = append(out, a)
		}
	}
	return out, errs
}

// runtimeDetail adds a runtime's role and status from GetAgentRuntime.
// Environment variables are kept by name only.
func runtimeDetail(ctx context.Context, cl *bedrockagentcorecontrol.Client, region, id string, a *Agent) error {
	d, err := cl.GetAgentRuntime(ctx, &bedrockagentcorecontrol.GetAgentRuntimeInput{AgentRuntimeId: aws.String(id)})
	if err != nil {
		a.Evidence = append(a.Evidence, "bedrock-agentcore:GetAgentRuntime failed ("+errCode(err)+"): execution role unknown")
		return awsErr(region, "bedrock-agentcore:GetAgentRuntime "+id, err)
	}
	a.Identity = aws.ToString(d.RoleArn)
	if d.Status != "" {
		a.Status = string(d.Status)
	}
	if d.LastUpdatedAt != nil {
		a.Updated = *d.LastUpdatedAt
	}
	a.Evidence = append(a.Evidence, "execution role from bedrock-agentcore:GetAgentRuntime")
	if names := keyNames(d.EnvironmentVariables); len(names) > 0 {
		a.Evidence = append(a.Evidence, "environment variable names: "+strings.Join(names, ", "))
	}
	return nil
}

// keyNames returns the sorted keys of m; the values are dropped.
func keyNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// awsConsole links to a resource in the AWS console (commercial partition
// only).
func awsConsole(partition, region, service, fragment string) string {
	if partition != "aws" {
		return ""
	}
	r := url.QueryEscape(region)
	return "https://" + r + ".console.aws.amazon.com/" + service + "/home?region=" + r + "#" + fragment
}

// errCode is the AWS error code, or "error" when there is none.
func errCode(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) && api.ErrorCode() != "" {
		return api.ErrorCode()
	}
	return "error"
}

// awsErr names the region and call of a failed AWS request.
func awsErr(region, call string, err error) error {
	var api smithy.APIError
	if errors.As(err, &api) {
		return fmt.Errorf("aws %s: %s: %s: %s", region, call, api.ErrorCode(), api.ErrorMessage())
	}
	return fmt.Errorf("aws %s: %s: %w", region, call, err)
}

// sortAgents orders agents by cloud, account, region, kind and name.
func sortAgents(as []Agent) {
	key := func(a Agent) string {
		return strings.Join([]string{a.Cloud, a.Account, a.Region, a.Kind, a.Name, a.ID}, "\x00")
	}
	sort.SliceStable(as, func(i, j int) bool { return key(as[i]) < key(as[j]) })
}
