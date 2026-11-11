package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
)

// MachineID is a stable id for this machine that cannot be turned back into
// the OS machine id: sha256 over the OS id and salt (the workspace id once
// logged in, so two workspaces see unrelated ids for one machine).
func MachineID(salt string) string {
	raw := osMachineID()
	if raw == "" {
		raw, _ = os.Hostname()
	}
	sum := sha256.Sum256([]byte("authsec-cli\x00" + raw + "\x00" + salt))
	return hex.EncodeToString(sum[:16])
}

var (
	ioregUUID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)
	regGUID   = regexp.MustCompile(`MachineGuid\s+REG_SZ\s+(\S+)`)
)

func osMachineID() string {
	switch runtime.GOOS {
	case "linux":
		for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
			if b, err := os.ReadFile(p); err == nil && strings.TrimSpace(string(b)) != "" {
				return strings.TrimSpace(string(b))
			}
		}
	case "darwin":
		out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
		if m := ioregUUID.FindSubmatch(out); err == nil && m != nil {
			return string(m[1])
		}
	case "windows":
		out, err := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
		if m := regGUID.FindSubmatch(out); err == nil && m != nil {
			return string(m[1])
		}
	}
	return ""
}
