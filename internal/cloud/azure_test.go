package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const (
	rg     = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/"
	oaiID  = rg + "oai1"
	fndID  = rg + "found1"
	spchID = rg + "speech1"
)

// fakeAzure emulates the identity platform, Resource Manager and the
// Foundry data plane.
type fakeAzure struct {
	srv          *httptest.Server
	mu           sync.Mutex
	paths        []string
	tokenCalls   int
	foreignNext  bool // the accounts nextLink points to another host
	agentsStatus int  // when set, GET /agents of projA answers it
	noSubdomain  bool // found1 has no custom subdomain
}

func (f *fakeAzure) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodPost && r.URL.Path == "/tenant-1/oauth2/v2.0/token" {
		f.token(w, r)
		return
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(r.URL.Path, "/fd/") {
		version := "2025-05-01"
		if strings.HasSuffix(r.URL.Path, "/agents") {
			version = "v1"
		}
		if auth != "Bearer ai-tok" || r.URL.Query().Get("api-version") != version {
			azError(w, 401, "Unauthorized")
			return
		}
		f.foundry(w, r)
		return
	}
	if auth != "Bearer arm-tok" {
		azError(w, 401, "InvalidAuthenticationToken")
		return
	}
	f.arm(w, r)
}

func (f *fakeAzure) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.tokenCalls++
	f.mu.Unlock()
	_ = r.ParseForm()
	if r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("client_id") != "app-1" ||
		r.PostForm.Get("client_secret") != plantedAzure {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.","error_codes":[7000215]}`)
		return
	}
	switch r.PostForm.Get("scope") {
	case "https://management.azure.com/.default":
		fmt.Fprint(w, `{"token_type":"Bearer","access_token":"arm-tok"}`)
	case "https://ai.azure.com/.default":
		fmt.Fprint(w, `{"token_type":"Bearer","access_token":"ai-tok"}`)
	default:
		w.WriteHeader(400)
		fmt.Fprint(w, `{"error":"invalid_scope"}`)
	}
}

func (f *fakeAzure) arm(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("api-version") == "" {
		azError(w, 400, "MissingApiVersionParameter")
		return
	}
	switch r.URL.Path {
	case "/subscriptions":
		fmt.Fprint(w, `{"value":[{"subscriptionId":"s1","state":"Enabled"},{"subscriptionId":"s2","state":"Enabled"},{"subscriptionId":"s3","state":"Disabled"}]}`)
	case "/subscriptions/s1/providers/Microsoft.CognitiveServices/accounts":
		if r.URL.Query().Get("$skiptoken") == "" {
			next := f.srv.URL
			if f.foreignNext {
				next = "https://attacker.example"
			}
			fmt.Fprintf(w, `{"value":[{"id":%q,"name":"oai1","kind":"OpenAI","location":"eastus","identity":{"principalId":"pid-oai"}}],
				"nextLink":"%s/subscriptions/s1/providers/Microsoft.CognitiveServices/accounts?api-version=2025-06-01&$skiptoken=2"}`, oaiID, next)
			return
		}
		sub := "found1-sub"
		if f.noSubdomain {
			sub = ""
		}
		fmt.Fprintf(w, `{"value":[{"id":%q,"name":"found1","kind":"AIServices","location":"swedencentral",
			"properties":{"customSubDomainName":%q,"allowProjectManagement":true}},
			{"id":%q,"name":"speech1","kind":"SpeechServices","location":"eastus"}]}`, fndID, sub, spchID)
	case "/subscriptions/s2/providers/Microsoft.CognitiveServices/accounts":
		azError(w, 403, "AuthorizationFailed")
	case oaiID + "/deployments":
		fmt.Fprintf(w, `{"value":[{"id":%q,"name":"gpt4o","properties":{"model":{"format":"OpenAI","name":"gpt-4o","version":"2024-08-06"},
			"provisioningState":"Succeeded","deploymentState":"Running"},"systemData":{"lastModifiedAt":"2026-03-04T05:06:07Z"}}]}`, oaiID+"/deployments/gpt4o")
	case fndID + "/deployments":
		fmt.Fprintf(w, `{"value":[{"id":%q,"name":"mini","properties":{"model":{"name":"gpt-4o-mini"},"provisioningState":"Succeeded"}}]}`, fndID+"/deployments/mini")
	case fndID + "/projects":
		fmt.Fprintf(w, `{"value":[{"id":%q,"name":"found1/projA","location":"swedencentral","identity":{"principalId":"pid-projA"},
			"properties":{"displayName":"A","endpoints":{"AI Foundry API":"https://evil.example/api/projects/projA"}}},
			{"id":%q,"name":"found1/projB","location":"swedencentral"}]}`, fndID+"/projects/projA", fndID+"/projects/projB")
	default:
		azError(w, 404, "ResourceNotFound")
	}
}

func (f *fakeAzure) foundry(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/fd/found1-sub/api/projects/projA/assistants":
		if r.URL.Query().Get("after") == "" {
			fmt.Fprintf(w, `{"object":"list","data":[{"id":"asst_1","object":"assistant","created_at":1767225600,"name":"triage",
				"model":"mini","instructions":"%s","metadata":{"k":"%s"},"tools":[{"type":"file_search"},{"type":"code_interpreter"}]}],
				"first_id":"asst_1","last_id":"asst_1","has_more":true}`, plantedAzure, plantedAzure)
			return
		}
		fmt.Fprint(w, `{"object":"list","data":[{"id":"asst_2","object":"assistant","created_at":1767225601,"name":"","model":"mini","tools":[]}],
			"last_id":"asst_2","has_more":false}`)
	case "/fd/found1-sub/api/projects/projA/agents":
		if f.agentsStatus != 0 {
			azError(w, f.agentsStatus, "NotFound")
			return
		}
		fmt.Fprintf(w, `{"data":[{"object":"agent","id":"planner","name":"planner","state":"enabled",
			"instance_identity":{"principal_id":"pid-planner","client_id":"cid"},
			"versions":{"latest":{"version":"3","created_at":1767225700,"definition":{"kind":"prompt","model":"gpt-4.1",
			"instructions":"%s","tools":[{"type":"mcp","server_url":"https://mcp.example","headers":{"Authorization":"%s"}}]}}}}],
			"last_id":"planner","has_more":false}`, plantedAzure, plantedAzure)
	case "/fd/found1-sub/api/projects/projB/assistants", "/fd/found1-sub/api/projects/projB/agents":
		azError(w, 403, "PermissionDenied")
	default:
		azError(w, 404, "NotFound")
	}
}

func azError(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":{"code":%q,"message":"m"}}`, code)
}

func (f *fakeAzure) called(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.paths {
		if p == path {
			return true
		}
	}
	return false
}

// startAzure points the package at a fake Azure; runAz fails so a test that
// expects client credentials notices a CLI call.
func startAzure(t *testing.T) *fakeAzure {
	t.Helper()
	f := &fakeAzure{}
	f.srv = httptest.NewServer(f)
	t.Cleanup(f.srv.Close)
	oldARM, oldLogin, oldFD, oldAz := armBase, loginBase, foundryBase, runAz
	armBase, loginBase = f.srv.URL, f.srv.URL
	foundryBase = func(sub string) string { return f.srv.URL + "/fd/" + sub }
	runAz = func(context.Context, ...string) ([]byte, error) {
		t.Error("az was called")
		return nil, fmt.Errorf("no az")
	}
	t.Cleanup(func() { armBase, loginBase, foundryBase, runAz = oldARM, oldLogin, oldFD, oldAz })
	t.Setenv("AZURE_CLIENT_SECRET", plantedAzure)
	return f
}

func find(as []Agent, kind, name string) *Agent {
	for i := range as {
		if as[i].Kind == kind && as[i].Name == name {
			return &as[i]
		}
	}
	return nil
}

func TestDiscoverAzureClientCredentials(t *testing.T) {
	f := startAzure(t)
	agents, errs := DiscoverAzure(context.Background(), Azure{TenantID: "tenant-1", ClientID: "app-1", ClientSecretSet: true})
	noLeak(t, "agents", agents)
	noLeak(t, "errors", fmt.Sprint(errs))

	d := find(agents, "azure-openai-deployment", "gpt4o")
	if d == nil || d.Model != "gpt-4o (2024-08-06)" || d.Status != "Running" || d.Account != "s1" || d.Region != "eastus" ||
		d.Identity != "pid-oai" || d.Updated.IsZero() || d.Console != "https://portal.azure.com/#resource"+oaiID {
		t.Fatalf("gpt4o = %+v", d)
	}
	if m := find(agents, "azure-openai-deployment", "mini"); m == nil || m.Status != "Succeeded" {
		t.Fatalf("mini = %+v", m)
	}
	a := find(agents, "azure-foundry-agent", "triage")
	if a == nil || a.ID != fndID+"/projects/projA/assistants/asst_1" || a.Model != "mini" || a.Identity != "pid-projA" ||
		a.Region != "swedencentral" || a.Updated.Unix() != 1767225600 ||
		!strings.Contains(strings.Join(a.Evidence, ";"), "tools: code_interpreter, file_search") {
		t.Fatalf("triage = %+v", a)
	}
	if find(agents, "azure-foundry-agent", "asst_2") == nil {
		t.Fatalf("second page of agents missing: %+v", agents)
	}
	pl := find(agents, "azure-foundry-agent", "planner")
	if pl == nil || pl.ID != fndID+"/projects/projA/agents/planner" || pl.Model != "gpt-4.1" || pl.Identity != "pid-planner" ||
		pl.Status != "enabled" || pl.Updated.Unix() != 1767225700 ||
		!strings.Contains(strings.Join(pl.Evidence, ";"), "kind prompt;latest version 3;tools: mcp") {
		t.Fatalf("planner (GET /agents) = %+v", pl)
	}
	if len(agents) != 5 {
		t.Fatalf("agents = %+v", agents)
	}
	es := fmt.Sprint(errs)
	if len(errs) != 2 || !strings.Contains(es, "not permitted to list Cognitive Services accounts in subscription s2") ||
		!strings.Contains(es, "not permitted to list agents of project projB") || !strings.Contains(es, "PermissionDenied") {
		t.Fatalf("errors = %v", errs)
	}
	if f.called(spchID+"/deployments") || f.called("/subscriptions/s3/providers/Microsoft.CognitiveServices/accounts") {
		t.Fatal("read a speech account or a disabled subscription")
	}
	if f.tokenCalls != 2 {
		t.Fatalf("token requests = %d, want one per audience", f.tokenCalls)
	}
}

func TestDiscoverAzureCLI(t *testing.T) {
	f := startAzure(t)
	var calls []string
	runAz = func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		switch {
		case strings.Contains(strings.Join(args, " "), "--resource https://management.azure.com/ "):
			return []byte(`{"accessToken":"arm-tok","tokenType":"Bearer"}`), nil
		case strings.Contains(strings.Join(args, " "), "--resource https://ai.azure.com "):
			return []byte(`{"accessToken":"ai-tok","tokenType":"Bearer"}`), nil
		}
		return nil, fmt.Errorf("unexpected az call")
	}
	agents, errs := DiscoverAzure(context.Background(), Azure{TenantID: "tenant-1", SubscriptionIDs: []string{"s1"}})
	if len(errs) != 1 || len(agents) != 5 {
		t.Fatalf("agents=%+v errs=%v", agents, errs)
	}
	if f.called("/subscriptions") || f.tokenCalls != 0 {
		t.Fatal("listed subscriptions or used client credentials although subscriptions were given")
	}
	want := "account get-access-token --resource https://management.azure.com/ --output json --tenant tenant-1"
	if len(calls) != 2 || calls[0] != want {
		t.Fatalf("az calls = %q", calls)
	}
}

func TestDiscoverAzureBadSecret(t *testing.T) {
	startAzure(t)
	t.Setenv("AZURE_CLIENT_SECRET", plantedAWS) // wrong, and must not be echoed
	agents, errs := DiscoverAzure(context.Background(), Azure{TenantID: "tenant-1", ClientID: "app-1", ClientSecretSet: true})
	if len(agents) != 0 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "invalid_client") {
		t.Fatalf("agents=%v errs=%v", agents, errs)
	}
	noLeak(t, "errors", errs[0].Error())
}

func TestDiscoverAzureForeignNextLink(t *testing.T) {
	f := startAzure(t)
	f.foreignNext = true
	_, errs := DiscoverAzure(context.Background(), Azure{TenantID: "tenant-1", ClientID: "app-1", ClientSecretSet: true, SubscriptionIDs: []string{"s1"}})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "outside Azure Resource Manager") {
		t.Fatalf("errs = %v", errs)
	}
}

func TestDiscoverAzureFoundryTokenAskedOnce(t *testing.T) {
	startAzure(t)
	n := 0
	runAz = func(_ context.Context, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "ai.azure.com") {
			n++
			return nil, fmt.Errorf("AADSTS: consent required")
		}
		return []byte(`{"accessToken":"arm-tok"}`), nil
	}
	agents, errs := DiscoverAzure(context.Background(), Azure{SubscriptionIDs: []string{"s1"}})
	if n != 1 || len(errs) != 1 || len(agents) != 2 || !strings.Contains(errs[0].Error(), "consent required") {
		t.Fatalf("n=%d agents=%d errs=%v", n, len(agents), errs)
	}
}

func TestDiscoverAzureNoLoginReportedOnce(t *testing.T) {
	startAzure(t)
	n := 0
	runAz = func(context.Context, ...string) ([]byte, error) {
		n++
		return nil, fmt.Errorf("Please run 'az login' to setup account.")
	}
	agents, errs := DiscoverAzure(context.Background(), Azure{SubscriptionIDs: []string{"s1", "s2"}})
	if n != 1 || len(agents) != 0 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "az login") {
		t.Fatalf("n=%d agents=%v errs=%v", n, agents, errs)
	}
}

func TestDiscoverAzureAgentsListNotOffered(t *testing.T) {
	for _, status := range []int{400, 404} {
		f := startAzure(t)
		f.agentsStatus = status
		agents, errs := DiscoverAzure(context.Background(), Azure{TenantID: "tenant-1", ClientID: "app-1", ClientSecretSet: true, SubscriptionIDs: []string{"s1"}})
		if len(agents) != 4 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "projB") {
			t.Fatalf("status %d: agents=%d errs=%v", status, len(agents), errs)
		}
	}
}

func TestDiscoverAzureNoSubdomain(t *testing.T) {
	f := startAzure(t)
	f.noSubdomain = true
	agents, errs := DiscoverAzure(context.Background(), Azure{TenantID: "tenant-1", ClientID: "app-1", ClientSecretSet: true, SubscriptionIDs: []string{"s1"}})
	if len(agents) != 2 || len(errs) != 2 || !strings.Contains(fmt.Sprint(errs), "no valid custom subdomain") {
		t.Fatalf("agents=%d errs=%v", len(agents), errs)
	}
	for _, p := range f.paths {
		if strings.HasPrefix(p, "/fd/") {
			t.Fatalf("called the data plane without a subdomain: %s", p)
		}
	}
}

func TestOnARM(t *testing.T) {
	old := armBase
	armBase = "https://management.azure.com"
	t.Cleanup(func() { armBase = old })
	if !onARM("https://management.azure.com:443/subscriptions/s1?x=1") || !onARM("https://MANAGEMENT.azure.com/x") {
		t.Fatal("the ARM host with its default port was refused")
	}
	for _, bad := range []string{"https://management.azure.com.evil.example/x", "https://management.azure.com@evil.example/x",
		"http://management.azure.com/x", "https://management.azure.com:8443/x", "https://evil.example/x", "https:x", "/relative"} {
		if onARM(bad) {
			t.Errorf("onARM(%q) accepted", bad)
		}
	}
}

func TestFoundryErr(t *testing.T) {
	deny := &httpStatusError{Status: 403, Code: "PermissionDenied"}
	missing := &httpStatusError{Status: 404}
	other := &httpStatusError{Status: 500}
	cases := []struct {
		c, n  error
		want  string
		isNil bool
	}{
		{nil, nil, "", true},
		{nil, missing, "", true},
		{missing, nil, "", true},
		{deny, deny, "HTTP 403", false},
		{missing, missing, "HTTP 404", false},
		{nil, deny, "(GET /agents): HTTP 403", false},
		{other, nil, "(GET /assistants): HTTP 500", false},
		{other, deny, "HTTP 403", false},
		{other, other, "HTTP 500\nHTTP 500", false},
	}
	for i, c := range cases {
		err := foundryErr("list agents", c.c, c.n)
		if c.isNil != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.want)) {
			t.Errorf("case %d: %v", i, err)
		}
	}
}

func TestDNSLabel(t *testing.T) {
	for s, want := range map[string]bool{"found1-sub": true, "A1": true, "": false, "-a": false, "a-": false,
		"evil.example": false, "a@b": false, "a:80": false, strings.Repeat("a", 64): false} {
		if dnsLabel(s) != want {
			t.Errorf("dnsLabel(%q) = %v", s, !want)
		}
	}
}

func TestWithoutSecrets(t *testing.T) {
	env := []string{"PATH=/bin", "AWS_SECRET_ACCESS_KEY=" + plantedAWS, "AZURE_CLIENT_SECRET=" + plantedAzure,
		"aws_access_key_id=x", "AWS_SESSION_TOKEN=t", "AZURE_TENANT_ID=t1"}
	got := withoutSecrets(env)
	if strings.Join(got, ";") != "PATH=/bin;AZURE_TENANT_ID=t1" {
		t.Fatalf("got %v", got)
	}
}

func TestRunAzDropsSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a shell script as az")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "env.txt")
	script := "#!/bin/sh\nenv > '" + out + "'\necho '{\"accessToken\":\"tok\"}'\n"
	if err := os.WriteFile(filepath.Join(dir, "az"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("AWS_SECRET_ACCESS_KEY", plantedAWS)
	t.Setenv("AZURE_CLIENT_SECRET", plantedAzure)
	t.Setenv("AZURE_TENANT_ID", "kept")
	tok, err := cliToken(context.Background(), Azure{}, armResource)
	if err != nil || tok != "tok" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
	env, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), "AZURE_TENANT_ID=kept") {
		t.Fatalf("environment not passed: %s", env)
	}
	noLeak(t, "az environment", string(env))
}
