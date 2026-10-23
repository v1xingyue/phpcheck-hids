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

func TestCheckingScript(t *testing.T) {
	for _, tc := range []struct {
		os, arch, asset string
		corrupt         bool
		code            int
	}{
		{"Linux", "x86_64", "phpcheck-linux-amd64", false, 0},
		{"Linux", "i686", "phpcheck-linux-386", false, 0},
		{"Linux", "aarch64", "phpcheck-linux-arm64", false, 0},
		{"Darwin", "x86_64", "phpcheck-darwin-amd64", false, 0},
		{"Darwin", "arm64", "phpcheck-darwin-arm64", false, 1},
		{"Linux", "x86_64", "phpcheck-linux-amd64", true, 1},
		{"Darwin", "i386", "", false, 1},
		{"Linux", "mips", "", false, 1},
		{"Windows", "x86_64", "", false, 1},
	} {
		t.Run(fmt.Sprintf("%s-%s-corrupt%v", tc.os, tc.arch, tc.corrupt), func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			tmp := filepath.Join(root, "tmp")
			for _, dir := range []string{bin, tmp} {
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
			write(filepath.Join(bin, "uname"), "#!/bin/sh\ncase $1 in -s) echo \"$TEST_OS\";; -m) echo \"$TEST_ARCH\";; esac\n")
			write(filepath.Join(bin, "curl"), `#!/bin/sh
out=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --write-out) printf 'https://github.com/v1xingyue/phpcheck-hids/releases/tag/v0.2.0'; exit 0 ;;
    --output) out=$2; shift 2 ;;
    --proto|--proto-redir|--retry|--connect-timeout|--max-time) shift 2 ;;
    --*) shift ;;
    *) url=$1; shift ;;
  esac
done
printf '%s\n' "$url" >> "$TEST_REQUESTS"
cp "$TEST_FIXTURES/${url##*/}" "$out"
`)
			body := "#!/bin/sh\nprintf 'executed:%s\\n' \"$*\"\nexit " + fmt.Sprint(tc.code) + "\n"
			if tc.asset != "" {
				write(filepath.Join(root, tc.asset), body)
				sum := fmt.Sprintf("%x", sha256.Sum256([]byte(body)))
				if tc.corrupt {
					sum = strings.Repeat("0", 64)
				}
				write(filepath.Join(root, "SHA256SUMS"), sum+"  "+tc.asset+"\n")
			}
			cmd := exec.Command("sh", "checking.sh", "-probe", "http://127.0.0.1/probe.php")
			cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"), "TMPDIR="+tmp,
				"TEST_OS="+tc.os, "TEST_ARCH="+tc.arch, "TEST_FIXTURES="+root, "TEST_REQUESTS="+filepath.Join(root, "requests"))
			output, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					code = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tc.code {
				t.Fatalf("exit %d want %d: %s", code, tc.code, output)
			}
			executed := strings.Contains(string(output), "executed:-probe http://127.0.0.1/probe.php")
			if executed != (tc.asset != "" && !tc.corrupt) {
				t.Fatalf("unexpected execution: %s", output)
			}
			files, err := os.ReadDir(tmp)
			if err != nil || len(files) != 0 {
				t.Fatalf("temporary files not cleaned: %v %v", files, err)
			}
			if tc.asset != "" {
				requests, err := os.ReadFile(filepath.Join(root, "requests"))
				if err != nil || !strings.Contains(string(requests), "/v0.2.0/"+tc.asset) {
					t.Fatalf("wrong download: %s %v", requests, err)
				}
			}
		})
	}
}
