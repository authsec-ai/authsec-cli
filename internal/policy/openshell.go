package policy

import (
	"bytes"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// OpenShell policy (NVIDIA OpenShell, schema version 1), checked against
// crates/openshell-policy-schema at NVIDIA/OpenShell 8606ee3b (v0.1.8):
// version, filesystem_policy {include_workdir, read_only, read_write},
// landlock {compatibility}, network_policies {key: {name, endpoints[],
// binaries[]}}. Unknown keys are rejected by OpenShell, so only these are
// written. OpenShell is allow-only: there is no filesystem deny and no
// network deny, and every network rule names the binaries it applies to.

type osPolicy struct {
	Version          int               `yaml:"version"`
	FilesystemPolicy osFilesystem      `yaml:"filesystem_policy"`
	Landlock         osLandlock        `yaml:"landlock"`
	NetworkPolicies  map[string]osRule `yaml:"network_policies,omitempty"`
}

type osFilesystem struct {
	IncludeWorkdir bool     `yaml:"include_workdir"`
	ReadOnly       []string `yaml:"read_only"`
	ReadWrite      []string `yaml:"read_write"`
}

type osLandlock struct {
	Compatibility string `yaml:"compatibility"`
}

type osRule struct {
	Name      string       `yaml:"name"`
	Endpoints []osEndpoint `yaml:"endpoints"`
	Binaries  []osBinary   `yaml:"binaries"`
}

type osEndpoint struct {
	Host       string   `yaml:"host,omitempty"`
	Port       int      `yaml:"port"`
	AllowedIPs []string `yaml:"allowed_ips,omitempty"`
}

type osBinary struct {
	Path string `yaml:"path"`
}

// OpenShell's restrictive default filesystem (docs/how-it-works/policies/
// default-policy.mdx): kept so the agent's runtime still loads.
var (
	openshellReadOnly  = []string{"/bin", "/usr", "/lib", "/proc", "/dev/urandom", "/etc", "/var/log"}
	openshellReadWrite = []string{"/tmp", "/dev/null"}
	// Paths OpenShell adds at startup when a policy has network rules
	// (docs/how-it-works/policies/default-policy.mdx).
	openshellProxyBaseline = []string{"/usr", "/lib", "/etc", "/app", "/var/log", "/proc", "/dev/urandom", "/tmp", "/dev/null"}
	// Ports OpenShell blocks on exact-host and address endpoints.
	openshellBlockedPorts = map[int]bool{2379: true, 2380: true, 6443: true, 10250: true, 10255: true}
)

// AgentBinaries are where agent CLIs usually live inside an image. OpenShell
// matches the REAL path of the connecting executable or a parent; an npm
// install runs as node, so check with `readlink -f $(which claude)` in the
// image and pass --binary.
var AgentBinaries = map[string][]string{
	"claude-code": {"/usr/local/bin/claude", "/usr/bin/claude"},
	"codex":       {"/usr/local/bin/codex", "/usr/bin/codex"},
	"gemini-cli":  {"/usr/local/bin/gemini", "/usr/bin/gemini"},
	"opencode":    {"/usr/local/bin/opencode", "/usr/bin/opencode"},
	"aider":       {"/usr/local/bin/aider", "/usr/bin/aider"},
	"goose":       {"/usr/local/bin/goose", "/usr/bin/goose"},
}

// OpenShellOptions configures an export.
type OpenShellOptions struct {
	Home     string   // expands {home}: the home directory INSIDE the sandbox image
	Binaries []string // agent executables inside the image (real paths); default AgentBinaries
	Source   string   // the policy file, for the header
}

// OpenShellExport is an OpenShell policy and what could not be carried over.
type OpenShellExport struct {
	YAML  []byte
	Notes []string
}

// ExportOpenShell translates a policy into an OpenShell sandbox policy for
// `openshell sandbox create --policy`. Commands and MCP servers have no
// OpenShell equivalent and are reported in Notes (AuthSec's hooks enforce
// them).
func ExportOpenShell(p *Policy, opt OpenShellOptions) (*OpenShellExport, error) {
	var notes []string
	noted := map[string]bool{}
	note := func(format string, a ...any) {
		if n := fmt.Sprintf(format, a...); !noted[n] {
			noted[n] = true
			notes = append(notes, n)
		}
	}
	if p.Agent.ID == AnyAgent && len(opt.Binaries) == 0 {
		return nil, fmt.Errorf("the default policy names no agent binary: pass --binary with the agent's executable inside the image")
	}
	bins := opt.Binaries
	if len(bins) == 0 {
		bins = AgentBinaries[p.Agent.ID]
		if len(bins) == 0 {
			return nil, fmt.Errorf("no known executable path for %s: pass --binary with its real path inside the image", p.Agent.ID)
		}
		note("network rules apply to %s; check the real path in the image (readlink -f) and pass --binary if it differs (an npm install runs as node)", strings.Join(bins, ", "))
	}

	if opt.Home != "" && (!filepath.IsAbs(opt.Home) || strings.Contains(opt.Home, "..")) {
		return nil, fmt.Errorf("--home %q must be an absolute path inside the image", opt.Home)
	}
	out := osPolicy{Version: 1, Landlock: osLandlock{Compatibility: "best_effort"}}
	fs := &out.FilesystemPolicy

	// The project is the sandbox's working directory (the uploaded code).
	// It is writable there exactly when the policy lets the agent write
	// {project}, or when the policy has no path lists at all.
	noLists := len(p.Filesystem.ReadWrite) == 0 && len(p.Filesystem.ReadOnly) == 0
	projectRW := false
	for _, path := range p.Filesystem.ReadWrite {
		if path == "{project}" {
			projectRW = true
		}
	}
	fs.IncludeWorkdir = projectRW || noLists
	if noLists {
		note("the policy has no path lists: the sandbox gets OpenShell's default (system paths read-only, /tmp and the working directory writable)")
	} else if !projectRW {
		for _, path := range p.Filesystem.ReadOnly {
			if path == "{project}" {
				note("read_only {project}: OpenShell cannot make the working directory read-only; it is left out (include_workdir: false), so the agent cannot read the project either")
			}
		}
		if !fs.IncludeWorkdir {
			note("the policy does not let the agent write {project}: the sandbox working directory is not writable (include_workdir: false)")
		}
	}

	expand := func(path string) (string, bool) {
		if strings.Contains(path, "{project}") {
			if path != "{project}" {
				note("%s: skipped; the project is the sandbox working directory, whose inside OpenShell cannot list separately", path)
			}
			return "", false
		}
		if strings.Contains(path, "{home}") {
			if opt.Home == "" {
				note("%s: skipped; pass --home with the home directory inside the image", path)
				return "", false
			}
			path = strings.ReplaceAll(path, "{home}", opt.Home)
		}
		return filepath.Clean(path), true
	}
	var deny []string
	for _, d := range p.Filesystem.Deny {
		if strings.HasPrefix(d, "{project}") && fs.IncludeWorkdir {
			note("deny %s cannot be enforced: the working directory is writable as a whole in the sandbox", d)
			continue
		}
		if e, ok := expand(d); ok {
			deny = append(deny, e)
		}
	}
	add := func(list *[]string, path, kind string) {
		path = filepath.Clean(path)
		for _, d := range deny {
			if under(path, d) {
				note("%s %s: dropped, it is inside denied %s", kind, path, d)
				return
			}
		}
		for _, d := range deny {
			if under(d, path) && d != path {
				note("deny %s cannot be applied inside %s %s: OpenShell has no filesystem deny (Landlock is allow-only); narrow %s to keep it out", d, kind, path, path)
			}
		}
		if kind == "read_write" && path == "/" {
			note("read_write / is not allowed by OpenShell: dropped")
			return
		}
		for _, x := range *list {
			if x == path {
				return
			}
		}
		*list = append(*list, path)
	}
	for _, path := range openshellReadOnly {
		add(&fs.ReadOnly, path, "read_only")
	}
	for _, path := range openshellReadWrite {
		add(&fs.ReadWrite, path, "read_write")
	}
	for _, path := range p.Filesystem.ReadWrite {
		if e, ok := expand(path); ok {
			add(&fs.ReadWrite, e, "read_write")
		}
	}
	for _, path := range p.Filesystem.ReadOnly {
		if e, ok := expand(path); ok {
			add(&fs.ReadOnly, e, "read_only")
		}
	}
	if n := len(fs.ReadOnly) + len(fs.ReadWrite); n > 256 {
		return nil, fmt.Errorf("%d paths: OpenShell allows at most 256", n)
	}

	// Network: one rule for the agent. Host endpoints first; address ranges
	// are grouped per port into one host-less endpoint, because endpoints
	// that can match the same destination on a port must agree.
	var eps []osEndpoint
	seen := map[string]bool{}
	hostPorts := map[int]bool{}
	cidrs := map[int][]string{}
	var cidrPorts []int
	for _, r := range p.Network.Allow {
		port := r.Port
		label := r.Host + r.CIDR
		if port == 0 {
			port = 443
			note("allow %s: no port in the policy; exported as port 443 (OpenShell needs a port)", label)
		}
		if openshellBlockedPorts[port] {
			note("allow %s port %d: OpenShell always blocks this port (Kubernetes/etcd control plane)", label, port)
		}
		switch {
		case r.Host != "":
			h := strings.TrimSuffix(strings.ToLower(r.Host), ".")
			if h == "localhost" || strings.HasSuffix(h, ".localhost") {
				note("allow %s: OpenShell never allows loopback from a sandbox; skipped", r.Host)
				continue
			}
			if strings.HasPrefix(h, "*.") {
				if strings.Count(h, ".") < 2 {
					note("allow %s: OpenShell rejects wildcards on a top-level domain; skipped", r.Host)
					continue
				}
				h = "**." + strings.TrimPrefix(h, "*.") // any depth, as in AuthSec ("*." in OpenShell is one label)
			}
			key := fmt.Sprintf("%s|%d", h, port)
			if !seen[key] {
				seen[key] = true
				eps = append(eps, osEndpoint{Host: h, Port: port})
				hostPorts[port] = true
			}
		case r.CIDR != "":
			_, n, err := net.ParseCIDR(r.CIDR)
			if err != nil {
				continue
			}
			if reservedRange(n) {
				note("allow %s: overlaps loopback, link-local or unspecified addresses, which OpenShell never allows; skipped", r.CIDR)
				continue
			}
			if _, ok := cidrs[port]; !ok {
				cidrPorts = append(cidrPorts, port)
			}
			cidrs[port] = appendUnique(cidrs[port], n.String())
		}
	}
	for _, port := range cidrPorts {
		if hostPorts[port] {
			note("allow %s on port %d: not exported, because a host-less endpoint would overlap the host endpoints on that port; add these as host names", strings.Join(cidrs[port], ", "), port)
			continue
		}
		eps = append(eps, osEndpoint{AllowedIPs: cidrs[port], Port: port})
	}
	if len(p.Network.Deny) > 0 {
		var ds []string
		for _, r := range p.Network.Deny {
			ds = append(ds, r.Host+r.CIDR)
		}
		note("network deny rules (%s) are not exported: OpenShell allows only what is listed, so they hold unless an allow rule above covers them", strings.Join(ds, ", "))
	}
	if p.Network.Default == Allow {
		note("network default is allow, but OpenShell denies everything not listed: only the allow rules are reachable in the sandbox")
	}
	if len(eps) > 0 {
		rule := osRule{Name: "authsec " + p.Agent.ID, Endpoints: eps}
		for _, b := range bins {
			rule.Binaries = append(rule.Binaries, osBinary{Path: b})
		}
		out.NetworkPolicies = map[string]osRule{"authsec_" + ruleKey(p.Agent.ID): rule}
		// With network rules, OpenShell adds its proxy baseline paths at
		// startup whatever the policy says.
		for _, d := range deny {
			for _, b := range openshellProxyBaseline {
				if under(b, d) || under(d, b) {
					note("deny %s: OpenShell grants %s itself (its baseline for sandboxes with network rules), so it stays accessible", d, b)
				}
			}
		}
	} else {
		note("no network allow rules: the sandbox will have no outbound network")
	}

	if len(p.Commands.Deny)+len(p.Commands.Ask)+len(p.Commands.Allow) > 0 || len(p.MCPServers.Allow)+len(p.MCPServers.Deny) > 0 {
		note("commands and mcp_servers have no OpenShell equivalent; `authsec-cli run --enforce` applies them through the agent's hooks")
	}
	if p.Mode == Monitor {
		note("the policy is in monitor mode, but an OpenShell sandbox always enforces")
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "# OpenShell sandbox policy for %s, exported by authsec-cli", nameOr(p.Agent.Name, p.Agent.ID))
	if opt.Source != "" {
		fmt.Fprintf(&b, " from %s", opt.Source)
	}
	b.WriteString(".\n# Use: openshell sandbox create --policy <this file> --from <image with the agent> -- <agent>\n")
	for _, n := range notes {
		fmt.Fprintf(&b, "# note: %s\n", n)
	}
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(out); err != nil {
		return nil, err
	}
	return &OpenShellExport{YAML: b.Bytes(), Notes: notes}, nil
}

// reservedRange reports whether a range overlaps addresses OpenShell never
// authorises: loopback, link-local (cloud metadata included), unspecified.
func reservedRange(n *net.IPNet) bool {
	for _, r := range []string{"127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32", "::1/128", "::/128", "fe80::/10", "::ffff:127.0.0.0/104", "::ffff:169.254.0.0/112"} {
		_, rn, _ := net.ParseCIDR(r)
		if rn.Contains(n.IP) || n.Contains(rn.IP) {
			return true
		}
	}
	return false
}

func appendUnique(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

// ruleKey makes an OpenShell rule key from an agent id (no "_provider_"
// prefix, which OpenShell reserves).
func ruleKey(id string) string {
	var b strings.Builder
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
