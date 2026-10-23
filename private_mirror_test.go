package phpcheck

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateMirror(t *testing.T) {
	root := t.TempDir()
	fixtures, bin, static := filepath.Join(root, "fixtures"), filepath.Join(root, "bin"), filepath.Join(root, "static files")
	for _, dir := range []string{fixtures, bin} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(bin, "uname"), "#!/bin/sh\ncase $1 in -s) echo Linux;; -m) echo x86_64;; esac\n")
	write(filepath.Join(bin, "curl"), `#!/bin/sh
out=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --write-out) printf 'https://github.com/v1xingyue/phpcheck-hids/releases/tag/v0.3.0'; exit 0 ;;
    --output) out=$2; shift 2 ;;
    --proto|--proto-redir|--retry|--connect-timeout|--max-time) shift 2 ;;
    --*) shift ;;
    *) url=$1; shift ;;
  esac
done
printf '%s\n' "$url" >> "$TEST_REQUESTS"
cp "$TEST_FIXTURES/${url##*/}" "$out"
`)
	assets := []string{"phpcheck-linux-386", "phpcheck-linux-amd64", "phpcheck-linux-arm64", "phpcheck-darwin-amd64", "phpcheck-darwin-arm64", "checking.sh"}
	checking, err := os.ReadFile("checking.sh")
	if err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	for _, asset := range assets {
		body := []byte("#!/bin/sh\nprintf 'executed:%s\\n' \"$*\"\n")
		if asset == "checking.sh" {
			body = checking
		}
		write(filepath.Join(fixtures, asset), string(body))
		fmt.Fprintf(&manifest, "%x  %s\n", sha256.Sum256(body), asset)
	}
	write(filepath.Join(fixtures, "SHA256SUMS"), manifest.String())
	requests := filepath.Join(root, "requests")
	env := append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "TEST_REQUESTS="+requests)
	run := func(args ...string) ([]byte, error) {
		t.Helper()
		cmd := exec.Command("sh", append([]string{"prepare-private.sh"}, args...)...)
		cmd.Env = append(env, "TEST_FIXTURES="+fixtures)
		return cmd.CombinedOutput()
	}
	url := "http://mirror.internal:8080/phpcheck"
	if output, err := run("--url", url+"/", "--static-dir", static); err != nil {
		t.Fatalf("%s %v", output, err)
	}
	release := filepath.Join(static, "releases", "v0.3.0")
	entry, err := os.ReadFile(filepath.Join(static, "checking.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(entry), "download_base='"+url+"/releases/v0.3.0'") || !strings.Contains(string(entry), "release_version='v0.3.0'") {
		t.Fatalf("private URL/version not embedded: %s", entry)
	}
	privateManifest, err := os.ReadFile(filepath.Join(release, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range assets {
		body, err := os.ReadFile(filepath.Join(release, asset))
		if err != nil {
			t.Fatal(err)
		}
		line := fmt.Sprintf("%x  %s\n", sha256.Sum256(body), asset)
		if !strings.Contains(string(privateManifest), line) {
			t.Fatalf("private checksum incorrect: %s", asset)
		}
	}
	if string(privateManifest) == manifest.String() {
		t.Fatal("manifest not regenerated after rewriting script")
	}
	write(requests, "")
	cmd := exec.Command("sh", filepath.Join(static, "checking.sh"), "-h")
	cmd.Env = append(env, "TEST_FIXTURES="+release)
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "executed:-h") {
		t.Fatalf("private checker failed: %s %v", output, err)
	}
	downloads, err := os.ReadFile(requests)
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range strings.Fields(string(downloads)) {
		if !strings.HasPrefix(address, url+"/releases/v0.3.0/") {
			t.Fatalf("private checker used external address: %s", address)
		}
	}
	if _, err := run("--url", url, "--static-dir", static, "--version", "v0.3.0"); err == nil {
		t.Fatal("overwrote immutable release")
	}
	// A corrupt update must leave the currently published entry and version intact.
	write(filepath.Join(fixtures, "phpcheck-linux-amd64"), "corrupt")
	if _, err := run("--url", url, "--static-dir", static, "--version", "v0.3.1"); err == nil {
		t.Fatal("published corrupt update")
	}
	if _, err := os.Stat(filepath.Join(static, "releases", "v0.3.1")); !os.IsNotExist(err) {
		t.Fatalf("failed update was published: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(static, "checking.sh"))
	if err != nil || string(after) != string(entry) {
		t.Fatal("failed update changed live checker")
	}
	entries, err := os.ReadDir(filepath.Join(static, "releases"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("staging files leaked: %v %v", entries, err)
	}
	if _, err := os.Stat(filepath.Join(static, ".prepare-private.lock")); !os.IsNotExist(err) {
		t.Fatalf("publisher lock leaked: %v", err)
	}
	for _, badURL := range []string{"file:///tmp/phpcheck", "https://host/path'$(touch bad)", "https://user:secret@host/path", "https://host/path?x=1"} {
		if _, err := run("--url", badURL, "--static-dir", static); err == nil {
			t.Fatalf("accepted unsafe template input: %s", badURL)
		}
	}
}
