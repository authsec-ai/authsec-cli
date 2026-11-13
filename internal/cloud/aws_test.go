package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

const testAccount = "123456789012"

// fakeAWS emulates the operations used: STS and IAM (awsquery: form POST,
// XML reply) and Bedrock Agents and AgentCore control (restJson1).
type fakeAWS struct {
	mu            sync.Mutex
	calls         []string // one line per request
	keys          map[string]bool
	denyRegion    string // ListAgents answers 403 there
	deleteMissing bool   // DeleteRolePolicy answers NoSuchEntity
	leaked        bool   // a request carried the planted secret
}

var credRe = regexp.MustCompile(`Credential=([^/]+)/[0-9]+/([^/]+)/`)

func (f *fakeAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if strings.Contains(string(body)+r.URL.String()+fmt.Sprint(r.Header), plantedAWS) {
		f.mu.Lock()
		f.leaked = true
		f.mu.Unlock()
	}
	region := ""
	if m := credRe.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		f.mu.Lock()
		f.keys[m[1]] = true
		f.mu.Unlock()
		region = m[2]
	}
	if r.Method == http.MethodPost && r.URL.Path == "/" {
		f.query(w, string(body))
		return
	}
	f.record(fmt.Sprintf("%s %s %s", r.Method, r.URL.Path, region))
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/agents/":
		if region == f.denyRegion {
			restError(w, 403, "AccessDeniedException", "not authorized to perform bedrock:ListAgents")
			return
		}
		var in struct {
			NextToken string `json:"nextToken"`
		}
		_ = json.Unmarshal(body, &in)
		if in.NextToken == "" {
			fmt.Fprint(w, `{"agentSummaries":[{"agentId":"A1","agentName":"flights","agentStatus":"PREPARED","updatedAt":"2026-01-02T03:04:05Z"}],"nextToken":"p2"}`)
			return
		}
		fmt.Fprint(w, `{"agentSummaries":[{"agentId":"A2","agentName":"hotels","agentStatus":"NOT_PREPARED","updatedAt":"2026-01-01T00:00:00Z"}]}`)
	case r.Method == http.MethodGet && r.URL.Path == "/agents/A1/":
		fmt.Fprintf(w, `{"agent":{"agentArn":"arn:aws:bedrock:%s:%s:agent/A1","agentId":"A1","agentName":"flights",
			"agentResourceRoleArn":"arn:aws:iam::%s:role/service-role/AmazonBedrockExecutionRoleForAgents_flights",
			"agentStatus":"PREPARED","foundationModel":"anthropic.claude-3-5-sonnet","updatedAt":"2026-01-03T00:00:00Z",
			"instruction":"%s"}}`, region, testAccount, testAccount, plantedAWS)
	case r.Method == http.MethodGet && r.URL.Path == "/agents/A2/":
		restError(w, 403, "AccessDeniedException", "not authorized to perform bedrock:GetAgent")
	case r.Method == http.MethodPost && r.URL.Path == "/runtimes/":
		fmt.Fprintf(w, `{"agentRuntimes":[{"agentRuntimeArn":"arn:aws:bedrock-agentcore:%s:%s:runtime/R1","agentRuntimeId":"R1",
			"agentRuntimeName":"booker","agentRuntimeVersion":"1","status":"CREATING","lastUpdatedAt":"2026-02-01T00:00:00Z"}]}`, region, testAccount)
	case r.Method == http.MethodGet && r.URL.Path == "/runtimes/R1/":
		fmt.Fprintf(w, `{"agentRuntimeArn":"arn:aws:bedrock-agentcore:%s:%s:runtime/R1","agentRuntimeId":"R1","agentRuntimeName":"booker",
			"roleArn":"arn:aws:iam::%s:role/booker-runtime","status":"READY","lastUpdatedAt":"2026-02-02T00:00:00Z",
			"environmentVariables":{"OPENAI_API_KEY":"%s","LOG_LEVEL":"debug"}}`, region, testAccount, testAccount, plantedAWS)
	default:
		restError(w, 404, "ResourceNotFoundException", "no route")
	}
}

// query answers the awsquery operations.
func (f *fakeAWS) query(w http.ResponseWriter, body string) {
	form, _ := url.ParseQuery(body)
	action := form.Get("Action")
	f.record(strings.TrimSpace(strings.Join([]string{action, form.Get("RoleName"), form.Get("PolicyName"), form.Get("PolicyDocument")}, " ")))
	w.Header().Set("Content-Type", "text/xml")
	switch action {
	case "GetCallerIdentity":
		fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>
<Arn>arn:aws:iam::%s:user/auditor</Arn><UserId>AIDAFAKE</UserId><Account>%s</Account></GetCallerIdentityResult>
<ResponseMetadata><RequestId>r1</RequestId></ResponseMetadata></GetCallerIdentityResponse>`, testAccount, testAccount)
	case "PutRolePolicy":
		fmt.Fprint(w, `<PutRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>r2</RequestId></ResponseMetadata></PutRolePolicyResponse>`)
	case "DeleteRolePolicy":
		if f.deleteMissing {
			w.WriteHeader(404)
			fmt.Fprint(w, `<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>NoSuchEntity</Code>
<Message>The role policy with name AuthSecQuarantine cannot be found.</Message></Error><RequestId>r3</RequestId></ErrorResponse>`)
			return
		}
		fmt.Fprint(w, `<DeleteRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><ResponseMetadata><RequestId>r4</RequestId></ResponseMetadata></DeleteRolePolicyResponse>`)
	default:
		w.WriteHeader(400)
		fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>InvalidAction</Code><Message>unexpected</Message></Error></ErrorResponse>`)
	}
}

func (f *fakeAWS) record(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeAWS) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func restError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("X-Amzn-ErrorType", code)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"message":%q}`, msg)
}

// startAWS points the package at a fake AWS with fake credentials (the
// secret key is planted) and no real configuration files.
func startAWS(t *testing.T) *fakeAWS {
	t.Helper()
	f := &fakeAWS{keys: map[string]bool{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		if f.leaked {
			t.Error("a request carried the planted secret key")
		}
	})
	old := awsEndpoint
	awsEndpoint = srv.URL
	t.Cleanup(func() { awsEndpoint = old })
	dir := t.TempDir()
	for k, v := range map[string]string{
		"AWS_ACCESS_KEY_ID": "AKIDFAKE", "AWS_SECRET_ACCESS_KEY": plantedAWS, "AWS_SESSION_TOKEN": "",
		"AWS_CONFIG_FILE": filepath.Join(dir, "config"), "AWS_SHARED_CREDENTIALS_FILE": filepath.Join(dir, "credentials"),
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_PROFILE": "", "AWS_DEFAULT_PROFILE": "", "AWS_REGION": "", "AWS_DEFAULT_REGION": "",
	} {
		t.Setenv(k, v)
	}
	os.Unsetenv("AWS_SESSION_TOKEN")
	os.Unsetenv("AWS_PROFILE")
	os.Unsetenv("AWS_DEFAULT_PROFILE")
	return f
}

func byName(as []Agent, name, region string) *Agent {
	for i := range as {
		if as[i].Name == name && as[i].Region == region {
			return &as[i]
		}
	}
	return nil
}

func TestDiscoverAWS(t *testing.T) {
	f := startAWS(t)
	f.denyRegion = "eu-west-1"
	agents, errs := DiscoverAWS(context.Background(), AWS{Regions: []string{"us-east-1", "eu-west-1"}})
	noLeak(t, "agents", agents)
	noLeak(t, "errors", fmt.Sprint(errs))

	a1 := byName(agents, "flights", "us-east-1")
	if a1 == nil {
		t.Fatalf("flights not found: %+v", agents)
	}
	if a1.Kind != "bedrock-agent" || a1.ID != "arn:aws:bedrock:us-east-1:"+testAccount+":agent/A1" ||
		a1.Identity != "arn:aws:iam::"+testAccount+":role/service-role/AmazonBedrockExecutionRoleForAgents_flights" ||
		a1.Model != "anthropic.claude-3-5-sonnet" || a1.Status != "PREPARED" || a1.Account != testAccount ||
		a1.Updated.Format("2006-01-02") != "2026-01-03" || !strings.Contains(a1.Console, "#/agents/A1") {
		t.Fatalf("flights = %+v", a1)
	}
	a2 := byName(agents, "hotels", "us-east-1")
	if a2 == nil || a2.Identity != "" || !strings.Contains(strings.Join(a2.Evidence, ";"), "AccessDeniedException") {
		t.Fatalf("hotels (GetAgent denied) = %+v", a2)
	}
	for _, region := range []string{"us-east-1", "eu-west-1"} {
		r := byName(agents, "booker", region)
		if r == nil || r.Kind != "agentcore-runtime" || r.Identity != "arn:aws:iam::"+testAccount+":role/booker-runtime" ||
			r.Status != "READY" || r.ID != "arn:aws:bedrock-agentcore:"+region+":"+testAccount+":runtime/R1" {
			t.Fatalf("booker in %s = %+v", region, r)
		}
		if ev := strings.Join(r.Evidence, ";"); !strings.Contains(ev, "LOG_LEVEL, OPENAI_API_KEY") || strings.Contains(ev, "debug") {
			t.Fatalf("env evidence = %q", ev)
		}
	}
	if byName(agents, "flights", "eu-west-1") != nil {
		t.Fatal("agents listed in a denied region")
	}
	es := fmt.Sprint(errs)
	if len(errs) != 2 || !strings.Contains(es, "aws eu-west-1: bedrock:ListAgents: AccessDeniedException") ||
		!strings.Contains(es, "bedrock:GetAgent A2") {
		t.Fatalf("errors = %v", errs)
	}
}

func TestDiscoverAWSProfile(t *testing.T) {
	f := startAWS(t)
	os.Unsetenv("AWS_ACCESS_KEY_ID")
	os.Unsetenv("AWS_SECRET_ACCESS_KEY")
	creds := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	cfg := os.Getenv("AWS_CONFIG_FILE")
	if err := os.WriteFile(creds, []byte("[audit]\naws_access_key_id = AKIDAUDIT\naws_secret_access_key = "+plantedAWS+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("[profile audit]\nregion = ap-south-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agents, errs := DiscoverAWS(context.Background(), AWS{Profile: "audit"})
	if len(errs) != 1 { // GetAgent A2 is denied
		t.Fatalf("errors = %v", errs)
	}
	if byName(agents, "flights", "ap-south-1") == nil {
		t.Fatalf("profile region not used: %+v", agents)
	}
	if !f.keys["AKIDAUDIT"] || f.keys["AKIDFAKE"] {
		t.Fatalf("keys used: %v", f.keys)
	}
}

func TestDiscoverAWSNoRegion(t *testing.T) {
	startAWS(t)
	_, errs := DiscoverAWS(context.Background(), AWS{})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "AWS_REGIONS") {
		t.Fatalf("errors = %v", errs)
	}
}

func flightsAgent() Agent {
	return Agent{Cloud: "aws", Kind: "bedrock-agent", ID: "arn:aws:bedrock:us-east-1:" + testAccount + ":agent/A1", Region: "us-east-1",
		Account: testAccount, Identity: "arn:aws:iam::" + testAccount + ":role/service-role/flights-role"}
}

func TestQuarantineAWSDryRun(t *testing.T) {
	f := startAWS(t)
	p, err := QuarantineAWS(context.Background(), AWS{}, flightsAgent(), false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Applied || p.PolicyName != "AuthSecQuarantine" || len(f.callList()) != 0 {
		t.Fatalf("plan = %+v calls = %v", p, f.callList())
	}
	var doc struct {
		Statement []struct{ Effect, Action, Resource string }
	}
	if err := json.Unmarshal([]byte(p.PolicyDocument), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Statement) != 1 || doc.Statement[0].Effect != "Deny" || doc.Statement[0].Action != "*" || doc.Statement[0].Resource != "*" {
		t.Fatalf("document = %s", p.PolicyDocument)
	}
	if !strings.Contains(strings.Join(p.Actions, ";"), "flights-role") {
		t.Fatalf("actions = %v", p.Actions)
	}
}

func TestQuarantineAndReleaseAWSApply(t *testing.T) {
	f := startAWS(t)
	p, err := QuarantineAWS(context.Background(), AWS{}, flightsAgent(), true)
	if err != nil || !p.Applied {
		t.Fatalf("quarantine: %+v %v", p, err)
	}
	r, err := ReleaseAWS(context.Background(), AWS{}, flightsAgent(), true)
	if err != nil || !r.Applied {
		t.Fatalf("release: %+v %v", r, err)
	}
	want := []string{
		"GetCallerIdentity",
		"PutRolePolicy flights-role AuthSecQuarantine " + quarantineDocument,
		"GetCallerIdentity",
		"DeleteRolePolicy flights-role AuthSecQuarantine",
	}
	if got := f.callList(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	noLeak(t, "plan", []Plan{p, r})
}

func TestReleaseAWSAlreadyAbsent(t *testing.T) {
	f := startAWS(t)
	f.deleteMissing = true
	r, err := ReleaseAWS(context.Background(), AWS{}, flightsAgent(), true)
	if err != nil || !r.Applied || !strings.Contains(strings.Join(r.Actions, ";"), "nothing removed") {
		t.Fatalf("release: %+v %v", r, err)
	}
}

func TestQuarantineAWSRefuses(t *testing.T) {
	f := startAWS(t)
	other := flightsAgent()
	other.Identity = "arn:aws:iam::999999999999:role/flights-role"
	cases := map[string]Agent{
		"no role":       {Cloud: "aws", ID: "x"},
		"azure":         {Cloud: "azure", ID: "x", Identity: "0000"},
		"user arn":      {Cloud: "aws", ID: "x", Identity: "arn:aws:iam::" + testAccount + ":user/bob"},
		"other account": other,
	}
	for name, a := range cases {
		if _, err := QuarantineAWS(context.Background(), AWS{}, a, true); err == nil {
			t.Errorf("%s: quarantined", name)
		}
		if _, err := ReleaseAWS(context.Background(), AWS{}, a, true); err == nil {
			t.Errorf("%s: released", name)
		}
	}
	for _, c := range f.callList() {
		if !strings.HasPrefix(c, "GetCallerIdentity") {
			t.Fatalf("a refused plan made a change: %s", c)
		}
	}
}

func TestParseRole(t *testing.T) {
	r, err := parseRole("arn:aws-cn:iam::111122223333:role/a/b/name")
	if err != nil || r.Name != "name" || r.Account != "111122223333" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range []string{"", "arn:aws:iam::1:role/", "arn:aws:sts::1:assumed-role/x/y", "arn:aws:iam:::role/x"} {
		if _, err := parseRole(bad); err == nil {
			t.Errorf("parseRole(%q) accepted", bad)
		}
	}
}
