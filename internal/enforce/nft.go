package enforce

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// NetRules is the network policy of one enforced agent group.
type NetRules struct {
	Name       string // the group name; chains are named after it
	Cgroup     string // group path relative to the hierarchy root
	Quarantine bool   // drop everything, both ways
	// DefaultAllow: anything not in Deny goes out (network.default allow).
	// Otherwise only Allow goes out (network.default deny).
	DefaultAllow bool
	Allow        []Elem
	Deny         []Elem
	Resolvers    []net.IP // DNS servers the agent may query (port 53)
}

// Elem is an address or range and a port range (0-65535: any port and any
// protocol).
type Elem struct {
	Net            *net.IPNet
	PortLo, PortHi int
}

func (e Elem) anyPort() bool { return e.PortLo == 0 && e.PortHi == 65535 }

// TableName is the nftables table authsec-cli owns.
const TableName = "authsec"

// Script renders the whole table. It is applied in one nft transaction that
// first removes the old table, so rules never half-apply.
//
// Per group, outgoing: established flows pass (decisions are made when a
// connection starts); DNS to the configured resolvers passes; deny sets
// reject; with default deny, only the allow sets pass. Any-port entries are
// address-only sets, so they also cover protocols other than TCP and UDP.
// Incoming: new connections to an enforced agent are dropped except on
// loopback (local tools such as an IDE talk to agents there).
func Script(groups []NetRules) string {
	var b bytes.Buffer
	b.WriteString("add table inet " + TableName + "\ndelete table inet " + TableName + "\n")
	b.WriteString("table inet " + TableName + " {\n")
	sorted := append([]NetRules(nil), groups...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, g := range sorted {
		n := chainName(g.Name)
		a4, a4any, a6, a6any := split(g.Allow)
		d4, d4any, d6, d6any := split(g.Deny)
		writeConcatSet(&b, n+"_a4", "ipv4_addr", a4)
		writeConcatSet(&b, n+"_a6", "ipv6_addr", a6)
		writeConcatSet(&b, n+"_d4", "ipv4_addr", d4)
		writeConcatSet(&b, n+"_d6", "ipv6_addr", d6)
		writeAddrSet(&b, n+"_a4any", "ipv4_addr", a4any)
		writeAddrSet(&b, n+"_a6any", "ipv6_addr", a6any)
		writeAddrSet(&b, n+"_d4any", "ipv4_addr", d4any)
		writeAddrSet(&b, n+"_d6any", "ipv6_addr", d6any)
		var r4, r6 []*net.IPNet
		for _, ip := range g.Resolvers {
			if v4 := ip.To4(); v4 != nil {
				r4 = append(r4, &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)})
			} else {
				r6 = append(r6, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
		}
		writeAddrSet(&b, n+"_dns4", "ipv4_addr", r4)
		writeAddrSet(&b, n+"_dns6", "ipv6_addr", r6)

		fmt.Fprintf(&b, "\tchain %s {\n", n)
		if g.Quarantine {
			fmt.Fprintf(&b, "\t\tcounter log prefix \"authsec quarantine %s \" level info limit rate 10/second drop\n", n)
			b.WriteString("\t\tdrop\n\t}\n")
			fmt.Fprintf(&b, "\tchain in_%s {\n\t\tdrop\n\t}\n", n)
			continue
		}
		b.WriteString("\t\tct state established,related accept\n")
		fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } th dport 53 ip daddr @%s_dns4 accept\n", n)
		fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } th dport 53 ip6 daddr @%s_dns6 accept\n", n)
		fmt.Fprintf(&b, "\t\tip daddr @%s_d4any counter reject with icmpx admin-prohibited\n", n)
		fmt.Fprintf(&b, "\t\tip6 daddr @%s_d6any counter reject with icmpx admin-prohibited\n", n)
		fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } ip daddr . th dport @%s_d4 counter reject with icmpx admin-prohibited\n", n)
		fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } ip6 daddr . th dport @%s_d6 counter reject with icmpx admin-prohibited\n", n)
		if g.DefaultAllow {
			b.WriteString("\t\taccept\n")
		} else {
			fmt.Fprintf(&b, "\t\tip daddr @%s_a4any accept\n", n)
			fmt.Fprintf(&b, "\t\tip6 daddr @%s_a6any accept\n", n)
			fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } ip daddr . th dport @%s_a4 accept\n", n)
			fmt.Fprintf(&b, "\t\tmeta l4proto { tcp, udp } ip6 daddr . th dport @%s_a6 accept\n", n)
			fmt.Fprintf(&b, "\t\tcounter log prefix \"authsec deny %s \" level info limit rate 10/second reject with icmpx admin-prohibited\n", n)
			b.WriteString("\t\tcounter reject with icmpx admin-prohibited\n")
		}
		b.WriteString("\t}\n")
		fmt.Fprintf(&b, "\tchain in_%s {\n\t\tiif \"lo\" accept\n\t\tct state new counter drop\n\t}\n", n)
	}
	b.WriteString("\tchain output {\n\t\ttype filter hook output priority filter; policy accept;\n")
	for _, g := range sorted {
		fmt.Fprintf(&b, "\t\tsocket cgroupv2 level %d %q jump %s\n", cgroupLevel(g.Cgroup), g.Cgroup, chainName(g.Name))
	}
	b.WriteString("\t}\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n")
	for _, g := range sorted {
		fmt.Fprintf(&b, "\t\tsocket cgroupv2 level %d %q jump in_%s\n", cgroupLevel(g.Cgroup), g.Cgroup, chainName(g.Name))
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

func cgroupLevel(rel string) int { return strings.Count(strings.Trim(rel, "/"), "/") + 1 }

func chainName(group string) string {
	return "g_" + strings.NewReplacer("-", "_", ".", "_").Replace(group)
}

// split normalises elements into four disjoint groups: single-port IPv4 and
// IPv6 (address . port) and any-port IPv4 and IPv6 (address only). v4-mapped
// IPv6 addresses become IPv4. Overlapping entries, which nft rejects in an
// interval set, are removed: a range covered by a wider range of the same
// port (or by any-port) goes.
func split(elems []Elem) (v4, v4any, v6, v6any []Elem) {
	for _, e := range elems {
		e = normalise(e)
		if e.Net == nil {
			continue
		}
		is4 := e.Net.IP.To4() != nil
		switch {
		case e.anyPort() && is4:
			v4any = append(v4any, e)
		case e.anyPort():
			v6any = append(v6any, e)
		case is4:
			v4 = append(v4, e)
		default:
			v6 = append(v6, e)
		}
	}
	v4any, v6any = dropCovered(v4any, nil), dropCovered(v6any, nil)
	v4, v6 = dropCovered(v4, v4any), dropCovered(v6, v6any)
	return
}

func normalise(e Elem) Elem {
	if e.Net == nil {
		return e
	}
	ones, bits := e.Net.Mask.Size()
	if v4 := e.Net.IP.To4(); v4 != nil && bits == 128 {
		if ones < 96 {
			return Elem{} // a v4-mapped range wider than all of IPv4 is meaningless
		}
		e.Net = &net.IPNet{IP: v4.Mask(net.CIDRMask(ones-96, 32)), Mask: net.CIDRMask(ones-96, 32)}
	} else if v4 != nil {
		e.Net = &net.IPNet{IP: v4.Mask(e.Net.Mask), Mask: e.Net.Mask}
	} else {
		e.Net = &net.IPNet{IP: e.Net.IP.Mask(e.Net.Mask), Mask: e.Net.Mask}
	}
	if e.PortHi < e.PortLo {
		e.PortLo, e.PortHi = e.PortHi, e.PortLo
	}
	return e
}

// dropCovered removes duplicates and entries contained in another entry of
// the same port, or in any entry of wider (any-port) coverage.
func dropCovered(es, wider []Elem) []Elem {
	var out []Elem
	for i, e := range es {
		covered := false
		for _, w := range wider {
			if netContains(w.Net, e.Net) {
				covered = true
			}
		}
		for j, o := range es {
			if i == j || o.PortLo > e.PortLo || o.PortHi < e.PortHi {
				continue
			}
			if netContains(o.Net, e.Net) && (!netContains(e.Net, o.Net) || j < i) {
				covered = true // strictly wider, or an identical earlier one
			}
		}
		if !covered {
			out = append(out, e)
		}
	}
	return out
}

func netContains(outer, inner *net.IPNet) bool {
	oo, ob := outer.Mask.Size()
	io, ib := inner.Mask.Size()
	return ob == ib && oo <= io && outer.Contains(inner.IP)
}

func elemAddr(n *net.IPNet) string {
	ones, bits := n.Mask.Size()
	if ones == bits {
		return n.IP.String()
	}
	return fmt.Sprintf("%s/%d", n.IP, ones)
}

func writeConcatSet(b *bytes.Buffer, name, typ string, elems []Elem) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s . inet_service\n\t\tflags interval\n", name, typ)
	var els []string
	for _, e := range elems {
		port := fmt.Sprint(e.PortLo)
		if e.PortHi != e.PortLo {
			port = fmt.Sprintf("%d-%d", e.PortLo, e.PortHi)
		}
		els = append(els, elemAddr(e.Net)+" . "+port)
	}
	writeElements(b, els)
}

func writeAddrSet(b *bytes.Buffer, name, typ string, nets interface{}) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n\t\tflags interval\n\t\tauto-merge\n", name, typ)
	var els []string
	switch v := nets.(type) {
	case []Elem:
		for _, e := range v {
			els = append(els, elemAddr(e.Net))
		}
	case []*net.IPNet:
		for _, n := range v {
			els = append(els, elemAddr(n))
		}
	}
	writeElements(b, els)
}

func writeElements(b *bytes.Buffer, els []string) {
	sort.Strings(els)
	var out []string
	for i, e := range els {
		if i == 0 || e != els[i-1] {
			out = append(out, e)
		}
	}
	if len(out) > 0 {
		fmt.Fprintf(b, "\t\telements = { %s }\n", strings.Join(out, ", "))
	}
	b.WriteString("\t}\n")
}

// Firewall applies scripts. NFT runs the nft binary.
type Firewall interface {
	Apply(script string) error
	Remove() error
}

// NFT applies scripts with `nft -f -`.
type NFT struct{ Binary string }

func (n NFT) bin() string {
	if n.Binary != "" {
		return n.Binary
	}
	for _, p := range []string{"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "nft"
}

// Apply loads a script atomically.
func (n NFT) Apply(script string) error {
	cmd := exec.Command(n.bin(), "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Remove deletes the table (no agent is enforced any more).
func (n NFT) Remove() error {
	cmd := exec.Command(n.bin(), "-f", "-")
	cmd.Stdin = strings.NewReader("add table inet " + TableName + "\ndelete table inet " + TableName + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Resolvers returns the DNS servers of /etc/resolv.conf (127.0.0.53 with
// systemd-resolved).
func Resolvers(resolvConf string) []net.IP {
	b, err := os.ReadFile(resolvConf)
	if err != nil {
		return nil
	}
	var out []net.IP
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(strings.Split(f[1], "%")[0]); ip != nil {
				out = append(out, ip)
			}
		}
	}
	return out
}
