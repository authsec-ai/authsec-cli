package collector

import (
	"fmt"
	"net"
	"path"
	"sort"
	"strings"

	"github.com/authsec-ai/authsec-cli/internal/policy"
)

// Control kinds a receipt reports, and their states.
const (
	ctlEgress     = "egress"
	ctlExec       = "exec"
	ctlFilesystem = "filesystem"
	ctlSecret     = "secret"
	ctlAdmission  = "admission"
	ctlBroker     = "broker"

	stateApplied     = "applied"
	stateObserving   = "observing"
	stateUnsupported = "unsupported"
)

// Translation is a delivery turned into an authsec-cli policy, with what
// each control became.
type Translation struct {
	Policy   *policy.Policy
	Document []byte // the policy as YAML, checked
	Controls []ControlReceipt
	Notes    []string
}

// Translate maps a verified delivery onto the agent's policy, following the
// pinned template (decision.rego) exactly:
//
//   - deny beats require_approval beats allow, and anything no rule allows
//     is denied (default_deny) for an in-scope workload;
//   - network.connect rules match by resource; the controls artifact
//     resolved each resource to an address and port (egress);
//   - file.* rules match a path, or a prefix written path/**;
//   - exec rules match every program, or under the path-aware template
//     only the program at their path (Data.ExecByPath);
//   - secret.read, admission and broker have no host enforcement here and
//     are reported unsupported.
//
// require_approval has no human in the loop on a host: commands become
// "ask" (the Claude Code hook asks), network and files are denied.
func Translate(agentID, mode string, d *Data, c *Controls, controlsSHA string) (*Translation, error) {
	p := &policy.Policy{
		APIVersion: policy.APIVersion,
		Kind:       policy.Kind,
		Agent:      policy.AgentRef{ID: agentID, Name: agentID},
		Mode:       policy.Monitor,
		Network:    policy.Network{Default: policy.Deny},
		Commands:   policy.Commands{Default: policy.Deny},
		MCPServers: policy.MCPServers{Default: policy.Allow},
	}
	state := stateObserving
	switch mode {
	case "enforce":
		p.Mode, state = policy.Enforce, stateApplied
	case "observe", "":
	default:
		return nil, fmt.Errorf("delivery mode %q is not observe or enforce", mode)
	}
	t := &Translation{Policy: p}
	receipt := func(kind, st, test string) {
		t.Controls = append(t.Controls, ControlReceipt{Kind: kind, State: st, ArtifactSHA256: controlsSHA, Test: test})
	}

	// Egress.
	for _, e := range c.Egress {
		r := policy.Rule{Port: e.Port}
		addr := strings.TrimSpace(e.Address)
		switch {
		case addr == "":
			t.Notes = append(t.Notes, fmt.Sprintf("egress rule %s has no address; skipped", e.RuleID))
			continue
		case net.ParseIP(addr) != nil:
			// A single address is a /32 (or /128) range in a policy.
			if net.ParseIP(addr).To4() != nil {
				r.CIDR = addr + "/32"
			} else {
				r.CIDR = addr + "/128"
			}
		default:
			if _, _, err := net.ParseCIDR(addr); err == nil {
				r.CIDR = addr
			} else {
				r.Host = addr
			}
		}
		if e.Protocol != "" && !strings.EqualFold(e.Protocol, "tcp") {
			t.Notes = append(t.Notes, fmt.Sprintf("egress rule %s is %s; only TCP is enforced, it is logged", e.RuleID, e.Protocol))
		}
		if e.Effect == "allow" {
			p.Network.Allow = append(p.Network.Allow, r)
		} else {
			p.Network.Deny = append(p.Network.Deny, r) // deny, and require_approval without a human
		}
	}
	receipt(ctlEgress, state, fmt.Sprintf("nftables per agent cgroup: %d allowed, %d denied, others denied", len(p.Network.Allow), len(p.Network.Deny)))

	// Exec.
	execTest := translateExec(p, d, t)
	receipt(ctlExec, state, "programs the agent starts: "+execTest)

	// Filesystem: rules from data.json (they carry the action), baseline
	// paths read-only.
	ro := map[string]bool{}
	rw := map[string]bool{}
	deny := map[string]bool{}
	for _, r := range d.Rules {
		if !strings.HasPrefix(r.Action, "file.") || r.Path == "" {
			continue
		}
		path := strings.TrimSuffix(r.Path, "/**")
		switch r.Effect {
		case "allow":
			if r.Action == "file.write" || r.Action == "file.read_write" {
				rw[path] = true
			} else {
				ro[path] = true
			}
		default:
			deny[path] = true
		}
	}
	b := c.Filesystem.Baseline
	for _, l := range b.Loaders {
		ro[l] = true
	}
	for _, list := range [][]string{b.Libraries, b.Certificates, b.ReadonlyConfig} {
		for _, x := range list {
			ro[x] = true
		}
	}
	p.Filesystem.ReadOnly, p.Filesystem.ReadWrite, p.Filesystem.Deny = keys(ro), keys(rw), keys(deny)
	receipt(ctlFilesystem, state, fmt.Sprintf("%d read-only, %d read-write, %d denied paths; running agents are logged, run --enforce confines", len(ro), len(rw), len(deny)))

	// What a host does not enforce.
	for _, r := range d.Rules {
		switch r.Action {
		case "secret.read":
			receipt(ctlSecret, stateUnsupported, "secret access is brokered, not enforced on the host: rule "+r.ID)
		case "admission":
			receipt(ctlAdmission, stateUnsupported, "admission applies to clusters: rule "+r.ID)
		}
	}
	if len(c.Broker) > 0 {
		receipt(ctlBroker, stateUnsupported, fmt.Sprintf("%d broker rules are served by the gateway", len(c.Broker)))
	}

	doc, err := policy.Marshal(p)
	if err != nil {
		return nil, err
	}
	if _, issues := policy.Parse(doc); len(issues) > 0 {
		for _, i := range issues {
			if !i.Warning {
				return nil, fmt.Errorf("the translated policy is not valid: %s", i)
			}
			t.Notes = append(t.Notes, i.String())
		}
	}
	t.Document = doc
	return t, nil
}

// translateExec maps exec rules onto command rules. An exec rule without a
// path (or any exec rule, under the original template) covers every
// program, and the most restrictive of those decides for all of them. A rule
// with a path is about that program: commands match program names, so
// /usr/bin/zsh becomes "zsh" and "zsh *". Template precedence holds: deny
// beats require_approval beats allow, and a program no rule matches is
// denied.
func translateExec(p *policy.Policy, d *Data, t *Translation) string {
	every := ""
	var named []DataRule
	for _, r := range d.Rules {
		if r.Action != "exec" {
			continue
		}
		if d.ExecByPath && r.Path != "" {
			named = append(named, r)
			continue
		}
		if rank(r.Effect) > rank(every) {
			every = r.Effect
		}
	}
	switch every {
	case "deny":
		// Every program matches a deny: nothing else can allow one.
		p.Commands.Default = policy.Deny
		return "deny (every program)"
	case "require_approval":
		p.Commands.Default = policy.Allow
		p.Commands.Ask = []string{"*"}
	case "allow":
		p.Commands.Default = policy.Allow
	default:
		p.Commands.Default = policy.Deny
	}
	var allow, ask, deny []string
	for _, r := range named {
		if strings.HasSuffix(r.Path, "/**") || strings.HasSuffix(r.Path, "/") {
			t.Notes = append(t.Notes, fmt.Sprintf("exec rule %s names the programs under %s; commands are matched by program name, so it is not applied", r.ID, r.Path))
			continue
		}
		name := strings.ReplaceAll(path.Base(r.Path), "*", `\*`)
		if name == "" || name == "." || name == "/" {
			t.Notes = append(t.Notes, fmt.Sprintf("exec rule %s has no program name in %q; not applied", r.ID, r.Path))
			continue
		}
		pats := []string{name, name + " *"}
		switch r.Effect {
		case "deny":
			deny = append(deny, pats...)
		case "require_approval":
			ask = append(ask, pats...)
		default:
			allow = append(allow, pats...)
		}
	}
	if every == "" || every == "allow" {
		// Under an every-program allow, a named allow changes nothing.
		if every == "" {
			p.Commands.Allow = dedupe(allow)
		}
		p.Commands.Ask = dedupe(ask)
	}
	p.Commands.Deny = dedupe(deny)
	if every == "" {
		return fmt.Sprintf("%d programs allowed, %d need approval, %d denied, others denied", len(p.Commands.Allow)/2, len(p.Commands.Ask)/2, len(p.Commands.Deny)/2)
	}
	return fmt.Sprintf("%s (every program), %d denied by name", every, len(p.Commands.Deny)/2)
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func rank(effect string) int {
	switch effect {
	case "deny":
		return 3
	case "require_approval":
		return 2
	case "allow":
		return 1
	}
	return 0
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
