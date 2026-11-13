package cloud

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

// maxEnvBytes caps the .env file read.
const maxEnvBytes = 1 << 20

// secretKeys are exported into the process environment for the SDK and the
// token call. They never enter Config.
var secretKeys = []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET"}

// LoadEnv reads cloud settings from a .env file: KEY=VALUE lines, with
// comments, quotes and an optional "export " prefix. A key missing from the
// file falls back to the process environment. Secret variables present in
// the file are set in the process environment (os.Setenv) for the SDK and
// the token call; Config only says whether the Azure client secret is set.
// Warnings name keys and files, never values.
func LoadEnv(path string) (Config, []Warning, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, nil, fmt.Errorf("read %s: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxEnvBytes+1))
	if err != nil {
		return Config{}, nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxEnvBytes {
		return Config{}, nil, fmt.Errorf("read %s: larger than %d bytes", path, maxEnvBytes)
	}
	var warns []Warning
	if w, ok := modeWarning(f, path); ok {
		warns = append(warns, w)
	}
	file, pw := parseEnv(string(data))
	warns = append(warns, pw...)
	warns = append(warns, keyWarnings(file, path)...)
	for _, k := range secretKeys {
		if v, ok := file[k]; ok {
			if err := os.Setenv(k, v); err != nil {
				return Config{}, warns, fmt.Errorf("set %s in the environment: %w", k, err)
			}
		}
	}
	c, cw := buildConfig(file)
	return c, append(warns, cw...), nil
}

// modeWarning warns when other users may read or change the file.
func modeWarning(f *os.File, path string) (Warning, bool) {
	if runtime.GOOS == "windows" {
		return "", false
	}
	info, err := f.Stat()
	if err != nil {
		return "", false
	}
	perm := info.Mode().Perm()
	if perm&0o077 == 0 {
		return "", false
	}
	return Warning(fmt.Sprintf("%s can be read by other users (mode %04o): run chmod 600 %s", path, perm, path)), true
}

// keyWarnings recommends short-lived logins over keys held in the file.
func keyWarnings(file map[string]string, path string) []Warning {
	var out []Warning
	var aws []string
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} {
		if _, ok := file[k]; ok {
			aws = append(aws, k)
		}
	}
	if len(aws) > 0 {
		out = append(out, Warning(fmt.Sprintf("%s holds long-lived AWS keys (%s): prefer AWS_PROFILE with an SSO profile (aws configure sso)",
			path, strings.Join(aws, ", "))))
	}
	if _, ok := file["AZURE_CLIENT_SECRET"]; ok {
		out = append(out, Warning(fmt.Sprintf("%s holds an Azure client secret (AZURE_CLIENT_SECRET): prefer 'az login'", path)))
	}
	return out
}

// buildConfig maps the variables to Config. When AUTHSEC_CLOUDS is set in
// neither the file nor the environment, the clouds are inferred from the
// keys the file sets.
func buildConfig(file map[string]string) (Config, []Warning) {
	get := func(k string) string {
		if v, ok := file[k]; ok {
			return v
		}
		return os.Getenv(k)
	}
	first := func(keys ...string) string {
		for _, k := range keys {
			if v := get(k); v != "" {
				return v
			}
		}
		return ""
	}
	c := Config{
		AWS: AWS{
			Profile: get("AWS_PROFILE"),
			Regions: splitList(first("AWS_REGIONS", "AWS_REGION", "AWS_DEFAULT_REGION")),
		},
		Azure: Azure{
			TenantID:        get("AZURE_TENANT_ID"),
			SubscriptionIDs: splitList(first("AZURE_SUBSCRIPTION_IDS", "AZURE_SUBSCRIPTION_ID")),
			ClientID:        get("AZURE_CLIENT_ID"),
			ClientSecretSet: os.Getenv("AZURE_CLIENT_SECRET") != "",
		},
	}
	var warns []Warning
	if v := get("AUTHSEC_CLOUDS"); v != "" {
		c.Clouds, warns = parseClouds(v)
	} else {
		c.Clouds = inferClouds(file)
	}
	return c, warns
}

// parseClouds reads AUTHSEC_CLOUDS. Unknown names are dropped with a warning
// that does not repeat them.
func parseClouds(v string) ([]string, []Warning) {
	var out []string
	var warns []Warning
	for _, name := range splitList(strings.ToLower(v)) {
		switch name {
		case "aws", "azure":
			out = append(out, name)
		default:
			warns = append(warns, "AUTHSEC_CLOUDS names a cloud that is not supported (only aws and azure): ignored")
		}
	}
	return out, warns
}

// inferClouds picks the clouds whose keys the file sets.
func inferClouds(file map[string]string) []string {
	has := func(keys ...string) bool {
		for _, k := range keys {
			if _, ok := file[k]; ok {
				return true
			}
		}
		return false
	}
	var out []string
	if has("AWS_PROFILE", "AWS_REGIONS", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID") {
		out = append(out, "aws")
	}
	if has("AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_IDS", "AZURE_SUBSCRIPTION_ID", "AZURE_CLIENT_ID") {
		out = append(out, "azure")
	}
	return out
}

// parseEnv reads KEY=VALUE lines. Lines it cannot read are skipped with a
// warning that gives the line number only.
func parseEnv(data string) (map[string]string, []Warning) {
	out := map[string]string{}
	var warns []Warning
	for i, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, err := parseLine(line)
		if err != "" {
			warns = append(warns, Warning(fmt.Sprintf(".env line %d %s: ignored", i+1, err)))
			continue
		}
		out[key] = val
	}
	return out, warns
}

// parseLine splits one line. err is a short reason, never the line itself.
func parseLine(line string) (key, val, err string) {
	for _, p := range []string{"export ", "export\t"} {
		if strings.HasPrefix(line, p) {
			line = strings.TrimSpace(line[len(p):])
		}
	}
	eq := strings.IndexByte(line, '=')
	if eq <= 0 {
		return "", "", "is not KEY=VALUE"
	}
	key = strings.TrimSpace(line[:eq])
	if !validKey(key) {
		return "", "", "has an invalid key"
	}
	rest := strings.TrimSpace(line[eq+1:])
	switch {
	case strings.HasPrefix(rest, `"`):
		v, ok := unquoteDouble(rest[1:])
		if !ok {
			return "", "", "has an unterminated quote"
		}
		return key, v, ""
	case strings.HasPrefix(rest, "'"):
		end := strings.IndexByte(rest[1:], '\'')
		if end < 0 {
			return "", "", "has an unterminated quote"
		}
		return key, rest[1 : 1+end], ""
	}
	for _, c := range []string{" #", "\t#"} {
		if i := strings.Index(rest, c); i >= 0 {
			rest = rest[:i]
		}
	}
	return key, strings.TrimSpace(rest), ""
}

// unquoteDouble reads a double-quoted value up to its closing quote,
// handling \n, \t, \\ and \" escapes.
func unquoteDouble(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			return b.String(), true
		case c == '\\' && i+1 < len(s):
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", false
}

// validKey reports whether k is a shell variable name.
func validKey(k string) bool {
	for i, r := range k {
		ok := r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return k != ""
}
