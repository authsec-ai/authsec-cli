package cloud

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

const (
	plantedAWS   = "PLANTEDawsSECRETvalue0123456789doNOTleak"
	plantedAzure = "PLANTEDazureSECRET~value.doNOTleak"
)

// clearEnv empties every variable LoadEnv reads, for this test only.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"AUTHSEC_CLOUDS", "AWS_PROFILE", "AWS_REGIONS", "AWS_REGION", "AWS_DEFAULT_REGION",
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_TENANT_ID", "AZURE_SUBSCRIPTION_IDS",
		"AZURE_SUBSCRIPTION_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

func writeEnv(t *testing.T, mode os.FileMode, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// noLeak fails when any planted secret appears in v's printed form.
func noLeak(t *testing.T, what string, v any) {
	t.Helper()
	s := fmt.Sprintf("%+v %#v", v, v)
	for _, p := range []string{plantedAWS, plantedAzure} {
		if strings.Contains(s, p) {
			t.Fatalf("%s leaks a planted secret: %s", what, s)
		}
	}
}

func TestLoadEnvParses(t *testing.T) {
	clearEnv(t)
	p := writeEnv(t, 0o600, `# cloud settings
AUTHSEC_CLOUDS="aws, Azure"

export AWS_PROFILE=audit   # SSO profile
AWS_REGIONS=us-east-1, eu-west-1,us-east-1
export	AZURE_TENANT_ID='tenant-1 # not a comment'
AZURE_SUBSCRIPTION_IDS="sub-1,sub-2"
AZURE_CLIENT_ID = app-1
`)
	c, w, err := LoadEnv(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	want := Config{
		Clouds: []string{"aws", "azure"},
		AWS:    AWS{Profile: "audit", Regions: []string{"us-east-1", "eu-west-1"}},
		Azure:  Azure{TenantID: "tenant-1 # not a comment", SubscriptionIDs: []string{"sub-1", "sub-2"}, ClientID: "app-1"},
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatalf("got %+v\nwant %+v", c, want)
	}
}

func TestLoadEnvFallbacks(t *testing.T) {
	clearEnv(t)
	t.Setenv("AWS_PROFILE", "from-shell")
	p := writeEnv(t, 0o600, "AWS_REGION=ap-south-1\nAZURE_SUBSCRIPTION_ID=sub-9\n")
	c, _, err := LoadEnv(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.AWS.Profile != "from-shell" || !reflect.DeepEqual(c.AWS.Regions, []string{"ap-south-1"}) {
		t.Fatalf("aws: %+v", c.AWS)
	}
	if !reflect.DeepEqual(c.Azure.SubscriptionIDs, []string{"sub-9"}) {
		t.Fatalf("azure: %+v", c.Azure)
	}
	if !reflect.DeepEqual(c.Clouds, []string{"aws", "azure"}) {
		t.Fatalf("inferred clouds: %v", c.Clouds)
	}
}

func TestLoadEnvSecretsWarnedNeverKept(t *testing.T) {
	clearEnv(t)
	body := "AWS_ACCESS_KEY_ID=AKIDFAKE\nAWS_SECRET_ACCESS_KEY=\"" + plantedAWS + "\"\n" +
		"AZURE_CLIENT_ID=app\nAZURE_CLIENT_SECRET='" + plantedAzure + "'\n" +
		"AUTHSEC_CLOUDS=aws,azure,gcp-" + plantedAWS + "\n" +
		"BROKEN LINE " + plantedAzure + "\nBAD=\"" + plantedAWS + "\n"
	p := writeEnv(t, 0o644, body)
	c, w, err := LoadEnv(p)
	if err != nil {
		t.Fatal(err)
	}
	noLeak(t, "config", c)
	noLeak(t, "warnings", w)
	if !c.Azure.ClientSecretSet {
		t.Fatal("ClientSecretSet is false")
	}
	if os.Getenv("AWS_SECRET_ACCESS_KEY") != plantedAWS || os.Getenv("AZURE_CLIENT_SECRET") != plantedAzure {
		t.Fatal("secrets were not exported to the environment for the SDK")
	}
	all := fmt.Sprint(w)
	for _, s := range []string{"long-lived AWS keys", "AWS_SECRET_ACCESS_KEY", "az login", "not supported", "line 6", "line 7"} {
		if !strings.Contains(all, s) {
			t.Errorf("warnings miss %q: %v", s, w)
		}
	}
	if runtime.GOOS != "windows" && !strings.Contains(all, "chmod 600") {
		t.Errorf("no mode warning: %v", w)
	}
}

func TestLoadEnvPrivateFileNoModeWarning(t *testing.T) {
	clearEnv(t)
	p := writeEnv(t, 0o600, "AWS_PROFILE=x\n")
	_, w, err := LoadEnv(p)
	if err != nil || len(w) != 0 {
		t.Fatalf("w=%v err=%v", w, err)
	}
}

func TestLoadEnvMissingFile(t *testing.T) {
	_, _, err := LoadEnv(filepath.Join(t.TempDir(), "nope.env"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v", err)
	}
}

func TestParseLine(t *testing.T) {
	cases := []struct{ in, key, val, err string }{
		{`A=b`, "A", "b", ""},
		{`A="x\"y\\n\n"`, "A", "x\"y\\n\n", ""},
		{`A='$HOME #x'`, "A", "$HOME #x", ""},
		{`A=b # c`, "A", "b", ""},
		{`A=b#c`, "A", "b#c", ""},
		{`A=`, "A", "", ""},
		{`export A=1`, "A", "1", ""},
		{`=x`, "", "", "is not KEY=VALUE"},
		{`1A=x`, "", "", "has an invalid key"},
		{`A="x`, "", "", "has an unterminated quote"},
	}
	for _, c := range cases {
		k, v, e := parseLine(c.in)
		if k != c.key || v != c.val || e != c.err {
			t.Errorf("parseLine(%q) = %q %q %q", c.in, k, v, e)
		}
	}
}

func TestLoadEnvCloudsFromEnvironment(t *testing.T) {
	clearEnv(t)
	t.Setenv("AUTHSEC_CLOUDS", "azure")
	p := writeEnv(t, 0o600, "AWS_PROFILE=audit\nAZURE_TENANT_ID=t1\n")
	c, _, err := LoadEnv(p)
	if err != nil || !reflect.DeepEqual(c.Clouds, []string{"azure"}) {
		t.Fatalf("clouds = %v, err = %v", c.Clouds, err)
	}
	p = writeEnv(t, 0o600, "AUTHSEC_CLOUDS=aws\n")
	if c, _, _ = LoadEnv(p); !reflect.DeepEqual(c.Clouds, []string{"aws"}) {
		t.Fatalf("the file's AUTHSEC_CLOUDS did not win: %v", c.Clouds)
	}
}
