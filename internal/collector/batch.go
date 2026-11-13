package collector

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/authsec-ai/authsec-cli/internal/events"
	"github.com/authsec-ai/authsec-cli/internal/proc"
	"github.com/authsec-ai/authsec-cli/internal/recognise"
)

// instance is one running agent as the collector reports it.
type instance struct {
	agent  events.Agent
	object Object
	seen   time.Time
}

// objectFor builds the linux.process_group object of an agent's top
// process. The server fingerprints a host agent by exe, argv, unit, path
// and container id, so those are stable across restarts (no pid in argv,
// arguments scrubbed of credentials). The recogniser's verdict is an
// attribute: the server classifies on its own.
func objectFor(a events.Agent, p *proc.Process) Object {
	native := map[string]any{"pid": a.PID}
	attrs := map[string]any{"agent_id": a.ID, "agent_name": a.Name, "recognised_by": "authsec-cli"}
	if a.Confidence != "" {
		attrs["confidence"] = a.Confidence
	}
	if p != nil {
		if p.Exe != "" {
			native["exe"] = p.Exe
		}
		if args := recognise.ScrubArgs(p.Args); len(args) > 0 {
			native["argv"] = args
		}
		if p.Comm != "" {
			native["comm"] = p.Comm
		}
		if p.User != "" {
			native["user"] = p.User
		}
		if !p.Started.IsZero() {
			native["started_at"] = p.Started.UTC().Format(time.RFC3339)
		}
	} else if a.User != "" {
		native["user"] = a.User
	}
	if unit := systemdUnit(a.PID); unit != "" {
		native["systemd_unit"] = unit
	}
	return Object{Ref: fmt.Sprintf("o_p%d", a.PID), Kind: "linux.process_group", Native: native, Attributes: attrs}
}

// systemdUnit is the .service an agent runs in, from its cgroup ("" when
// it is not a service, as for an agent started in a terminal).
func systemdUnit(pid int) string {
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		for _, part := range strings.Split(sc.Text(), "/") {
			if strings.HasSuffix(part, ".service") && !strings.HasPrefix(part, "user@") {
				return part
			}
		}
	}
	return ""
}

// observationFor maps a daemon record onto the contract, or false when the
// record has no counterpart there (sensor notes; detections, which are the
// ITDR subsystem's; allow decisions, which repeat the activity record).
func observationFor(r events.Record, ref string) (Observation, bool) {
	ob := Observation{SubjectRef: ref, ObservedAt: r.Time.UTC().Format(time.RFC3339), Outcome: "success", Source: "authsec-cli"}
	rt := map[string]any{}
	if r.PID != 0 {
		rt["pid"] = r.PID
	}
	switch r.Type {
	case events.Process:
		ob.Kind = "runtime.process_exec"
		execFields(rt, r)
	case events.AgentStarted:
		ob.Kind = "runtime.process_exec"
		execFields(rt, r)
		rt["agent_start"] = true
	case events.AgentStopped:
		ob.Kind = "runtime.process_exit"
	case events.Network:
		ob.Kind = "runtime.network_connect"
		netFields(rt, r)
	case events.File:
		ob.Kind = "runtime.file_open"
		fileFields(rt, r)
	case events.Decision:
		switch r.Action {
		case "deny", "kill":
			if r.Enforced {
				ob.Outcome = "denied"
			} else {
				ob.Outcome = "attempted" // observe: it would have been denied
			}
		default:
			return Observation{}, false
		}
		switch r.Kind {
		case "network", "web":
			ob.Kind = "runtime.network_connect"
			netFields(rt, r)
		case "command":
			ob.Kind = "runtime.process_exec"
			execFields(rt, r)
		case "file":
			ob.Kind = "runtime.file_open"
			fileFields(rt, r)
		default:
			return Observation{}, false
		}
		rt["decision"] = r.Action
		if r.Rule != "" {
			rt["rule"] = r.Rule
		}
	default:
		return Observation{}, false
	}
	if len(rt) > 0 {
		ob.Runtime = rt
	}
	b, _ := json.Marshal(struct {
		R events.Record
		K string
	}{r, ob.Kind})
	ob.EventID = "acli-" + sha256Hex(b)[:32]
	return ob, true
}

func execFields(rt map[string]any, r events.Record) {
	if r.Comm != "" {
		rt["comm"] = r.Comm
	}
	if r.Exe != "" {
		rt["exe"] = r.Exe
	}
	if len(r.Args) > 0 {
		rt["argv"] = r.Args // already scrubbed by the daemon
	}
}

func netFields(rt map[string]any, r events.Record) {
	if r.Dst == nil {
		return
	}
	if r.Dst.IP != "" {
		rt["remote_ip"] = r.Dst.IP
	}
	if r.Dst.Port != 0 {
		rt["remote_port"] = r.Dst.Port
	}
	if r.Dst.Host != "" {
		rt["remote_host"] = r.Dst.Host
	}
	if r.Dst.Service != "" {
		rt["service"] = r.Dst.Service
	}
	if r.Dst.LLM {
		rt["llm_api"] = true
	}
	rt["protocol"] = "tcp"
}

func fileFields(rt map[string]any, r events.Record) {
	if r.Path != "" {
		rt["path"] = r.Path
	}
	if r.Access != "" {
		rt["access"] = r.Access
	}
	if r.Sensitive {
		rt["sensitive"] = true
	}
}
