package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Azure API versions and token audiences. Foundry's classic agents are
// GET {project endpoint}/assistants (Azure AI Agents 2025-05-01) and its
// newer agents GET {project endpoint}/agents (api-version v1), both with
// scope https://ai.azure.com/.default.
const (
	apiSubscriptions = "2022-12-01"
	apiCognitive     = "2025-06-01"
	apiAgents        = "2025-05-01"
	apiAgentsV1      = "v1"
	armResource      = "https://management.azure.com/"
	foundryResource  = "https://ai.azure.com"
	maxAzurePages    = 100
	maxAzureBody     = 32 << 20
	azTimeout        = 30 * time.Second
)

// runAz runs the Azure CLI and returns its standard output. A test seam.
var runAz = func(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, azTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "az", args...)
	cmd.Env = withoutSecrets(os.Environ())
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if errors.Is(err, exec.ErrNotFound) {
		return nil, errors.New("the Azure CLI (az) is not installed: install it and run 'az login', or set AZURE_CLIENT_ID and AZURE_CLIENT_SECRET")
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("az %s: %v: %s", args[0], err, msg)
	}
	return out, nil
}

// withoutSecrets drops the secret variables LoadEnv exports: the Azure
// CLI needs none of them.
func withoutSecrets(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		secret := false
		for _, s := range secretKeys {
			if strings.EqualFold(k, s) {
				secret = true
			}
		}
		if !secret {
			out = append(out, kv)
		}
	}
	return out
}

// errTokenReported is returned for a token that already failed: the first
// failure was reported, later calls are skipped without repeating it.
var errTokenReported = errors.New("token already failed")

// addErr appends err unless it is nil or a repeated token failure.
func addErr(errs []error, err error) []error {
	if err == nil || errors.Is(err, errTokenReported) {
		return errs
	}
	return append(errs, err)
}

// azSession holds the tokens of one discovery. A token that could not be
// had is asked for once and reported once.
type azSession struct {
	c      Azure
	tokens map[string]string
	failed map[string]error
}

// token returns a bearer token for resource: client credentials when a
// client id and secret are set, else the Azure CLI's login.
func (s *azSession) token(ctx context.Context, resource string) (string, error) {
	if t, ok := s.tokens[resource]; ok {
		return t, nil
	}
	if _, ok := s.failed[resource]; ok {
		return "", errTokenReported
	}
	var t string
	var err error
	if s.c.ClientID != "" && s.c.ClientSecretSet {
		t, err = clientCredentials(ctx, s.c, resource)
	} else {
		t, err = cliToken(ctx, s.c, resource)
	}
	if err != nil {
		err = fmt.Errorf("azure: token for %s: %w", resource, err)
		s.failed[resource] = err
		return "", err
	}
	s.tokens[resource] = t
	return t, nil
}

// clientCredentials asks the identity platform for an app-only token. The
// secret is read from the environment here and nowhere else.
func clientCredentials(ctx context.Context, c Azure, resource string) (string, error) {
	secret := os.Getenv("AZURE_CLIENT_SECRET")
	if c.TenantID == "" || secret == "" {
		return "", errors.New("client credentials need AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET")
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.ClientID},
		"client_secret": {secret},
		"scope":         {strings.TrimSuffix(resource, "/") + "/.default"},
	}
	u := loginBase + "/" + url.PathEscape(c.TenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Codes       []int  `json:"error_codes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("token response (HTTP %d): %w", resp.StatusCode, err)
	}
	if resp.StatusCode != http.StatusOK || body.AccessToken == "" {
		return "", fmt.Errorf("token refused (HTTP %d %s, AADSTS %v)", resp.StatusCode, body.Error, body.Codes)
	}
	return body.AccessToken, nil
}

// cliToken asks the Azure CLI for a token of the signed-in account.
func cliToken(ctx context.Context, c Azure, resource string) (string, error) {
	args := []string{"account", "get-access-token", "--resource", resource, "--output", "json"}
	if c.TenantID != "" {
		args = append(args, "--tenant", c.TenantID)
	}
	out, err := runAz(ctx, args...)
	if err != nil {
		return "", err
	}
	var body struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(out, &body); err != nil || body.AccessToken == "" {
		return "", errors.New("az account get-access-token returned no token: run 'az login'")
	}
	return body.AccessToken, nil
}

// httpStatusError is a non-200 Azure response.
type httpStatusError struct {
	Status int
	Code   string
}

func (e *httpStatusError) Error() string {
	s := fmt.Sprintf("HTTP %d", e.Status)
	if e.Code != "" {
		s += " " + e.Code
	}
	if e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden {
		s += " (not permitted)"
	}
	return s
}

// denied reports whether err is a 401 or 403.
func denied(err error) bool {
	var h *httpStatusError
	return errors.As(err, &h) && (h.Status == http.StatusUnauthorized || h.Status == http.StatusForbidden)
}

// getJSON GETs u with a bearer token and decodes the JSON body into out.
func getJSON(ctx context.Context, u, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, maxAzureBody)
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error json.RawMessage `json:"error"`
		}
		_ = json.NewDecoder(body).Decode(&e)
		return &httpStatusError{Status: resp.StatusCode, Code: errorCode(e.Error)}
	}
	return json.NewDecoder(body).Decode(out)
}

// errorCode reads the code of an ARM ({"code":...}) or OpenAI-style error.
func errorCode(raw json.RawMessage) string {
	var obj struct {
		Code json.RawMessage `json:"code"`
		Type string          `json:"type"`
	}
	if json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	var code string
	if json.Unmarshal(obj.Code, &code) == nil && code != "" {
		return code
	}
	return obj.Type
}

// armPage is one page of an ARM list.
type armPage[T any] struct {
	Value    []T    `json:"value"`
	NextLink string `json:"nextLink"`
}

// armList GETs every page of an ARM list. A nextLink to another host is
// refused so the token goes to ARM only.
func armList[T any](ctx context.Context, s *azSession, path, apiVersion string) ([]T, error) {
	tok, err := s.token(ctx, armResource)
	if err != nil {
		return nil, err
	}
	u := armBase + path + "?api-version=" + apiVersion
	var out []T
	for page := 0; u != "" && page < maxAzurePages; page++ {
		if !onARM(u) {
			return out, errors.New("nextLink points outside Azure Resource Manager")
		}
		var p armPage[T]
		if err := getJSON(ctx, u, tok, &p); err != nil {
			return out, err
		}
		out = append(out, p.Value...)
		u = p.NextLink
	}
	return out, nil
}

// onARM reports whether u is on the Resource Manager host: same scheme and
// host, no user info, and the same port (ARM's nextLinks may name :443).
func onARM(u string) bool {
	base, err := url.Parse(armBase)
	if err != nil {
		return false
	}
	t, err := url.Parse(u)
	if err != nil || t.User != nil || t.Opaque != "" || !strings.HasPrefix(t.Path, "/") {
		return false
	}
	return t.Scheme == base.Scheme && strings.EqualFold(t.Hostname(), base.Hostname()) && port(t) == port(base)
}

// port is u's port, or the scheme's default.
func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	if u.Scheme == "http" {
		return "80"
	}
	return "443"
}

// armIdentity is a resource's managed identity.
type armIdentity struct {
	PrincipalID string `json:"principalId"`
}

type armSubscription struct {
	SubscriptionID string `json:"subscriptionId"`
	State          string `json:"state"`
}

type armAccount struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Kind       string       `json:"kind"`
	Location   string       `json:"location"`
	Identity   *armIdentity `json:"identity"`
	Properties struct {
		CustomSubDomainName    string `json:"customSubDomainName"`
		AllowProjectManagement bool   `json:"allowProjectManagement"`
	} `json:"properties"`
}

type armDeployment struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		Model struct {
			Format  string `json:"format"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"model"`
		ProvisioningState string `json:"provisioningState"`
		DeploymentState   string `json:"deploymentState"`
	} `json:"properties"`
	SystemData struct {
		LastModifiedAt string `json:"lastModifiedAt"`
	} `json:"systemData"`
}

type armProject struct {
	ID         string       `json:"id"`
	Location   string       `json:"location"`
	Identity   *armIdentity `json:"identity"`
	Properties struct {
		DisplayName string `json:"displayName"`
	} `json:"properties"`
}

// foundryAgent is one agent of the Foundry data plane. Instructions,
// metadata and tool resources are deliberately not decoded.
type foundryAgent struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Model     string `json:"model"`
	CreatedAt int64  `json:"created_at"`
	Tools     []struct {
		Type string `json:"type"`
	} `json:"tools"`
}

// foundryAgentV1 is one agent of the newer Foundry model (GET /agents).
// Only the latest version's kind, model, tool types and creation time are
// decoded: never instructions, nor a tool's headers or keys.
type foundryAgentV1 struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	State            string `json:"state"`
	InstanceIdentity *struct {
		PrincipalID string `json:"principal_id"`
	} `json:"instance_identity"`
	Versions struct {
		Latest struct {
			Version    string `json:"version"`
			CreatedAt  int64  `json:"created_at"`
			Definition struct {
				Kind  string `json:"kind"`
				Model string `json:"model"`
				Tools []struct {
					Type string `json:"type"`
				} `json:"tools"`
			} `json:"definition"`
		} `json:"latest"`
	} `json:"versions"`
}

// foundryPage is one page of a Foundry data-plane list.
type foundryPage[T any] struct {
	Data    []T    `json:"data"`
	LastID  string `json:"last_id"`
	HasMore bool   `json:"has_more"`
}

// DiscoverAzure lists the Azure OpenAI deployments and Foundry agents of the
// listed subscriptions, or of every subscription the identity can list. A
// call that is not permitted or fails is collected and the rest is still
// read.
func DiscoverAzure(ctx context.Context, c Azure) ([]Agent, []error) {
	s := &azSession{c: c, tokens: map[string]string{}, failed: map[string]error{}}
	subs := c.SubscriptionIDs
	if len(subs) == 0 {
		var err error
		if subs, err = listSubscriptions(ctx, s); err != nil {
			return nil, []error{err}
		}
	}
	var agents []Agent
	var errs []error
	for _, sub := range subs {
		a, e := discoverSubscription(ctx, s, sub)
		agents = append(agents, a...)
		for _, err := range e {
			errs = addErr(errs, err)
		}
	}
	sortAgents(agents)
	return agents, errs
}

// listSubscriptions returns the subscriptions the identity can see, less
// disabled and deleted ones.
func listSubscriptions(ctx context.Context, s *azSession) ([]string, error) {
	list, err := armList[armSubscription](ctx, s, "/subscriptions", apiSubscriptions)
	if err != nil {
		return nil, fmt.Errorf("azure: list subscriptions: %w", err)
	}
	var out []string
	for _, sub := range list {
		if sub.SubscriptionID != "" && sub.State != "Disabled" && sub.State != "Deleted" {
			out = append(out, sub.SubscriptionID)
		}
	}
	return out, nil
}

// discoverSubscription reads the Cognitive Services accounts of one
// subscription.
func discoverSubscription(ctx context.Context, s *azSession, sub string) ([]Agent, []error) {
	path := "/subscriptions/" + url.PathEscape(sub) + "/providers/Microsoft.CognitiveServices/accounts"
	accounts, err := armList[armAccount](ctx, s, path, apiCognitive)
	if err != nil {
		return nil, []error{azErr("list Cognitive Services accounts in subscription "+sub, err)}
	}
	var agents []Agent
	var errs []error
	for _, acc := range accounts {
		kind := strings.ToLower(acc.Kind)
		if kind != "openai" && kind != "aiservices" {
			continue
		}
		a, err := deployments(ctx, s, sub, acc)
		agents, errs = append(agents, a...), addErr(errs, err)
		if kind == "aiservices" && acc.Properties.AllowProjectManagement {
			a, e := projects(ctx, s, sub, acc)
			agents, errs = append(agents, a...), append(errs, e...)
		}
	}
	return agents, errs
}

// deployments lists the model deployments of one account.
func deployments(ctx context.Context, s *azSession, sub string, acc armAccount) ([]Agent, error) {
	list, err := armList[armDeployment](ctx, s, acc.ID+"/deployments", apiCognitive)
	if err != nil {
		return nil, azErr("list deployments of account "+acc.Name, err)
	}
	var out []Agent
	for _, d := range list {
		a := Agent{
			Cloud:    "azure",
			Kind:     kindAzureDeployment,
			ID:       d.ID,
			Name:     d.Name,
			Region:   acc.Location,
			Account:  sub,
			Identity: principal(acc.Identity),
			Model:    modelName(d),
			Status:   firstNonEmpty(d.Properties.DeploymentState, d.Properties.ProvisioningState),
			Updated:  parseTime(d.SystemData.LastModifiedAt),
			Console:  portal(acc.ID),
			Evidence: []string{fmt.Sprintf("deployment of Cognitive Services account %s (kind %s)", acc.Name, acc.Kind)},
		}
		out = append(out, a)
	}
	return out, nil
}

// projects lists the Foundry projects of one account and their agents.
func projects(ctx context.Context, s *azSession, sub string, acc armAccount) ([]Agent, []error) {
	list, err := armList[armProject](ctx, s, acc.ID+"/projects", apiCognitive)
	if err != nil {
		return nil, []error{azErr("list Foundry projects of account "+acc.Name, err)}
	}
	var out []Agent
	var errs []error
	for _, p := range list {
		a, err := projectAgents(ctx, s, sub, acc, p)
		out, errs = append(out, a...), addErr(errs, err)
	}
	return out, errs
}

// projectAgents lists the agents of one Foundry project from its data plane:
// classic agents (GET /assistants) and agents of the newer Foundry model
// (GET /agents, api-version v1), which /assistants does not return. The
// endpoint is built from the account's subdomain, never taken from a
// response, so the token goes to Foundry only.
func projectAgents(ctx context.Context, s *azSession, sub string, acc armAccount, p armProject) ([]Agent, error) {
	project := lastSegment(p.ID)
	what := "list agents of project " + project
	subdomain := acc.Properties.CustomSubDomainName
	if !dnsLabel(subdomain) {
		return nil, fmt.Errorf("azure: %s: account %s has no valid custom subdomain", what, acc.Name)
	}
	tok, err := s.token(ctx, foundryResource)
	if err != nil {
		return nil, azErr(what, err)
	}
	base := foundryBase(subdomain) + "/api/projects/" + url.PathEscape(project)
	var out []Agent
	classic, errC := foundryList[foundryAgent](ctx, base+"/assistants", apiAgents, tok)
	for _, fa := range classic {
		out = append(out, foundryToAgent(sub, acc, p, fa))
	}
	current, errN := foundryList[foundryAgentV1](ctx, base+"/agents", apiAgentsV1, tok)
	for _, fa := range current {
		out = append(out, foundryV1ToAgent(sub, acc, p, fa))
	}
	return out, foundryErr(what, errC, errN)
}

// foundryErr merges the errors of the two agent lists. A list that the
// project does not offer (HTTP 400 or 404) is not an error when the other
// one was read, and one refusal is reported once.
func foundryErr(what string, classic, current error) error {
	switch {
	case classic == nil && current == nil:
		return nil
	case classic != nil && current != nil:
		if denied(classic) || notOffered(current) {
			return azErr(what, classic)
		}
		if denied(current) || notOffered(classic) {
			return azErr(what, current)
		}
		return azErr(what, errors.Join(classic, current))
	case classic != nil && !notOffered(classic):
		return azErr(what+" (GET /assistants)", classic)
	case current != nil && !notOffered(current):
		return azErr(what+" (GET /agents)", current)
	}
	return nil
}

// notOffered reports whether err is a 400 or 404: the API is not served
// for this project.
func notOffered(err error) bool {
	var h *httpStatusError
	return errors.As(err, &h) && (h.Status == http.StatusBadRequest || h.Status == http.StatusNotFound)
}

// foundryList GETs every page of a Foundry data-plane list.
func foundryList[T any](ctx context.Context, u, apiVersion, tok string) ([]T, error) {
	var out []T
	after := ""
	for page := 0; page < maxAzurePages; page++ {
		q := url.Values{"api-version": {apiVersion}, "limit": {"100"}}
		if after != "" {
			q.Set("after", after)
		}
		var fp foundryPage[T]
		if err := getJSON(ctx, u+"?"+q.Encode(), tok, &fp); err != nil {
			return out, err
		}
		out = append(out, fp.Data...)
		if !fp.HasMore || fp.LastID == "" || fp.LastID == after {
			break
		}
		after = fp.LastID
	}
	return out, nil
}

// dnsLabel reports whether s is one DNS label (letters, digits, hyphens).
func dnsLabel(s string) bool {
	if s == "" || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !(r == '-' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// foundryToAgent maps one data-plane agent. Agents act as their project's
// managed identity.
func foundryToAgent(sub string, acc armAccount, p armProject, fa foundryAgent) Agent {
	project := lastSegment(p.ID)
	a := Agent{
		Cloud:    "azure",
		Kind:     kindFoundryAgent,
		ID:       p.ID + "/assistants/" + fa.ID,
		Name:     firstNonEmpty(fa.Name, fa.ID),
		Region:   firstNonEmpty(p.Location, acc.Location),
		Account:  sub,
		Identity: principal(p.Identity),
		Model:    fa.Model,
		Console:  portal(p.ID),
		Evidence: []string{fmt.Sprintf("agent of Foundry project %s in account %s (GET /assistants)", project, acc.Name)},
	}
	if fa.CreatedAt > 0 {
		a.Updated = time.Unix(fa.CreatedAt, 0).UTC()
	}
	var tools []string
	for _, t := range fa.Tools {
		if t.Type != "" {
			tools = append(tools, t.Type)
		}
	}
	if len(tools) > 0 {
		sort.Strings(tools)
		a.Evidence = append(a.Evidence, "tools: "+strings.Join(tools, ", "))
	}
	return a
}

// foundryV1ToAgent maps one agent of the newer Foundry model. It acts as
// its own agent identity when it has one, else as its project's.
func foundryV1ToAgent(sub string, acc armAccount, p armProject, fa foundryAgentV1) Agent {
	project := lastSegment(p.ID)
	v := fa.Versions.Latest
	a := Agent{
		Cloud:    "azure",
		Kind:     kindFoundryAgent,
		ID:       p.ID + "/agents/" + fa.ID,
		Name:     firstNonEmpty(fa.Name, fa.ID),
		Region:   firstNonEmpty(p.Location, acc.Location),
		Account:  sub,
		Identity: principal(p.Identity),
		Model:    v.Definition.Model,
		Status:   fa.State,
		Console:  portal(p.ID),
		Evidence: []string{fmt.Sprintf("agent of Foundry project %s in account %s (GET /agents)", project, acc.Name)},
	}
	if fa.InstanceIdentity != nil && fa.InstanceIdentity.PrincipalID != "" {
		a.Identity = fa.InstanceIdentity.PrincipalID
		a.Evidence = append(a.Evidence, "identity: the agent's own Entra agent identity")
	}
	if v.CreatedAt > 0 {
		a.Updated = time.Unix(v.CreatedAt, 0).UTC()
	}
	if v.Definition.Kind != "" {
		a.Evidence = append(a.Evidence, "kind "+v.Definition.Kind)
	}
	if v.Version != "" {
		a.Evidence = append(a.Evidence, "latest version "+v.Version)
	}
	var tools []string
	for _, t := range v.Definition.Tools {
		if t.Type != "" {
			tools = append(tools, t.Type)
		}
	}
	if len(tools) > 0 {
		sort.Strings(tools)
		a.Evidence = append(a.Evidence, "tools: "+strings.Join(tools, ", "))
	}
	return a
}

// azErr describes a failed Azure call; a 401 or 403 says what to grant.
func azErr(what string, err error) error {
	if denied(err) {
		return fmt.Errorf("azure: not permitted to %s: %w: grant Reader (ARM) or Azure AI User (Foundry agents)", what, err)
	}
	return fmt.Errorf("azure: %s: %w", what, err)
}

func principal(id *armIdentity) string {
	if id == nil {
		return ""
	}
	return id.PrincipalID
}

func modelName(d armDeployment) string {
	m := d.Properties.Model
	if m.Name == "" {
		return ""
	}
	if m.Version != "" {
		return m.Name + " (" + m.Version + ")"
	}
	return m.Name
}

func portal(resourceID string) string {
	if resourceID == "" {
		return ""
	}
	return "https://portal.azure.com/#resource" + resourceID
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
