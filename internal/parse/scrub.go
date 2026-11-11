package parse

import (
	"math"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// Redacted replaces a value that is or may be a secret.
const Redacted = "<redacted>"

var (
	// Names that hold credentials: OPENAI_API_KEY, GITHUB_TOKEN, --password, ...
	sensitiveContains = regexp.MustCompile(`(?i)(token|secret|passw|pwd|credential|api[_-]?key|private[_-]?key|access[_-]?key|bearer|cookie|signature|client[_-]?secret|connection[_-]?string|database[_-]?url|(^|[_-])dsn$)`)
	sensitiveSegment  = regexp.MustCompile(`(?i)(^|[_.-])(key|auth|authorization|session|pat)($|[_.-])`)

	// Values that are recognisably credentials, whatever their name.
	knownSecret = regexp.MustCompile(`^(sk-[A-Za-z0-9_-]{8,}|sk_(live|test)_[A-Za-z0-9]{8,}|rk_(live|test)_[A-Za-z0-9]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|(AKIA|ASIA)[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{30,}|ya29\.[A-Za-z0-9_.-]{20,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*|aid_[A-Za-z0-9_-]{16,}|authsec_act_[A-Za-z0-9_-]{16,}|npm_[A-Za-z0-9]{20,}|hf_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}|-----BEGIN)`)
	tokenChars  = regexp.MustCompile(`^[A-Za-z0-9_+/=.-]+$`)
	urlUserinfo = regexp.MustCompile(`(://)[^/@\s]+@`)
	urlInText   = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)
	assignment  = regexp.MustCompile(`^(-{0,2}[A-Za-z_][A-Za-z0-9_.-]*)=(.*)$`)
	splitter    = regexp.MustCompile(`[\s"'(),;:=]+`)
	wordSep     = regexp.MustCompile(`[-_.]`)
	// Query parameters whose values are credentials whatever their length.
	sensitiveQuery = regexp.MustCompile(`(?i)^(code|sig|signature|state|x-amz-[a-z-]+|x-goog-[a-z-]+|se|sp|sv|sr|skoid|sktid)$`)
)

// SensitiveName reports whether a variable, header or flag name usually holds
// a credential.
func SensitiveName(name string) bool {
	name = strings.TrimLeft(name, "-")
	return sensitiveContains.MatchString(name) || sensitiveSegment.MatchString(name)
}

// LooksSecret reports whether a single token looks like a credential: a known
// key format, or a long random-looking string.
func LooksSecret(s string) bool {
	if knownSecret.MatchString(s) {
		return true
	}
	if len(s) < 24 || !tokenChars.MatchString(s) || strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") {
		return false
	}
	// A generic secret is one long random run. Word-structured names
	// (103_add_user_flow_permissions.sql) and UUIDs split into short parts.
	longest := ""
	for _, seg := range wordSep.Split(s, -1) {
		if len(seg) > len(longest) {
			longest = seg
		}
	}
	if len(longest) < 20 {
		return false
	}
	s = longest
	var letters, digits bool
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			digits = true
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			letters = true
		}
	}
	return letters && digits && entropy(s) >= 3.7
}

func entropy(s string) float64 {
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	var h float64
	n := float64(len([]rune(s)))
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// URL keeps a URL's scheme, host and path. User info is dropped; a query
// value is kept only when it is short, its name is not a credential's and it
// does not look like one.
func URL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Text(raw)
	}
	u.User = nil
	u.Fragment = ""
	if u.RawQuery != "" {
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			for _, v := range q[k] {
				if v != "" && !SensitiveName(k) && !sensitiveQuery.MatchString(k) && !LooksSecret(v) && len(v) <= 32 {
					parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
				} else {
					parts = append(parts, url.QueryEscape(k)+"="+Redacted)
				}
			}
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	return u.String()
}

// Text scrubs free text such as a hook command or a permission rule: URLs are
// reduced as URL does, NAME=value pairs with a sensitive name lose the value,
// and any word that looks like a credential is replaced.
func Text(s string) string {
	s = urlInText.ReplaceAllStringFunc(s, func(u string) string {
		if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
			return URL(u)
		}
		return urlUserinfo.ReplaceAllString(u, "${1}"+Redacted+"@")
	})
	words := strings.Fields(s)
	changed := false
	for i, w := range words {
		if m := assignment.FindStringSubmatch(w); m != nil && SensitiveName(m[1]) && m[2] != "" && m[2] != Redacted {
			words[i], changed = m[1]+"="+Redacted, true
			continue
		}
		for _, tok := range splitter.Split(w, -1) {
			if tok != "" && LooksSecret(tok) {
				words[i], changed = strings.ReplaceAll(words[i], tok, Redacted), true
			}
		}
	}
	if !changed {
		return s
	}
	return strings.Join(words, " ")
}

// Args scrubs a command's arguments: the value after a sensitive flag
// (--api-key VALUE), the value of a sensitive assignment (--token=VALUE,
// GITHUB_TOKEN=VALUE), and anything Text would remove.
func Args(args []string) []string {
	out := make([]string, len(args))
	for i, a := range args {
		if i > 0 && strings.HasPrefix(args[i-1], "-") && !strings.Contains(args[i-1], "=") && SensitiveName(args[i-1]) && !strings.HasPrefix(a, "-") {
			out[i] = Redacted
			continue
		}
		if m := assignment.FindStringSubmatch(a); m != nil && SensitiveName(m[1]) && m[2] != "" {
			out[i] = m[1] + "=" + Redacted
			continue
		}
		out[i] = Text(a)
	}
	return out
}

// Names returns the sorted keys of an object: environment variables and
// headers are reported by name only.
func Names(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SensitiveNames returns the names among names that usually hold a credential.
func SensitiveNames(names []string) []string {
	var out []string
	for _, n := range names {
		if SensitiveName(n) {
			out = append(out, n)
		}
	}
	return out
}
