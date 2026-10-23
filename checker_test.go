package phpcheck

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVersionStatus(t *testing.T) {
	cases := map[string]Status{
		"8.2.34": PotentiallyVulnerable, "8.2.35": VersionSafe,
		"8.3.35": PotentiallyVulnerable, "8.3.36": VersionSafe,
		"8.4.26": PotentiallyVulnerable, "8.4.27": VersionSafe,
		"8.5.11": PotentiallyVulnerable, "8.5.12": VersionSafe,
		"8.2.100": VersionSafe, "8.1.99": PotentiallyVulnerable,
		"5.4.0": PotentiallyVulnerable, "5.6.40": PotentiallyVulnerable,
		"7.4.33": PotentiallyVulnerable, "8.0.30": PotentiallyVulnerable,
		"8.3.36-1ubuntu1": VersionSafe, "8.3.36RC1": Unknown,
		"8.3.36-rc1": Unknown, "8.3.36+dev": Unknown,
		"8.6.0": Unknown, "9.0.0": Unknown, "5.3.0": Unknown, "": Unknown,
		"8.3.999999999999999999999999": Unknown,
	}
	for v, want := range cases {
		if got := versionStatus(v); got != want {
			t.Errorf("%s: got %s want %s", v, got, want)
		}
	}
}

func str(s string) *string { return &s }

func TestMitigations(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *RuntimeConfig
		want Status
	}{
		{"no evidence", nil, PotentiallyVulnerable},
		{"both", &RuntimeConfig{str("0"), str("Off"), str("-1")}, ConfigMitigated},
		{"enabled", &RuntimeConfig{str("1"), str("1"), str("-1")}, PotentiallyVulnerable},
		{"late override", &RuntimeConfig{str("0"), str("1"), str("-1")}, PotentiallyVulnerable},
		{"finite memory", &RuntimeConfig{str("0"), str("0"), str("128M")}, PotentiallyVulnerable},
		{"missing directive", &RuntimeConfig{nil, str("0"), str("-1")}, PotentiallyVulnerable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := Instance{Version: "8.3.35", Config: tc.cfg}
			evaluate(&i)
			if i.Status != tc.want {
				t.Fatal(i)
			}
		})
	}
	for _, v := range []string{"8.3.36", "8.6.0"} {
		i := Instance{Version: v, Config: &RuntimeConfig{str("0"), str("0"), str("-1")}}
		evaluate(&i)
		if i.Status != versionStatus(v) {
			t.Fatal(i)
		}
	}
}

func TestAggregation(t *testing.T) {
	for _, tc := range []struct {
		items      []Instance
		incomplete bool
		want       Status
	}{
		{nil, false, NoPHP}, {nil, true, Unknown},
		{[]Instance{{Status: VersionSafe}, {Status: Unknown}}, false, Unknown},
		{[]Instance{{Status: VersionSafe}, {Status: ConfigMitigated}}, false, ConfigMitigated},
		{[]Instance{{Status: Unknown}, {Status: PotentiallyVulnerable}}, true, PotentiallyVulnerable},
	} {
		if got := aggregate(tc.items, tc.incomplete); got != tc.want {
			t.Fatalf("got %s want %s", got, tc.want)
		}
	}
}

func TestExtractVersion(t *testing.T) {
	for _, tc := range []struct {
		input, want string
		fail        bool
	}{
		{"X-Powered-By: PHP/8.3.36\x00", "8.3.36", false},
		{"random 8.3.36\x00", "", true},
		{"X-Powered-By: PHP/8.3.36\x00X-Powered-By: PHP/8.3.35\x00", "", true},
	} {
		v, err := extractVersion([]byte(tc.input))
		if (err != nil) != tc.fail || v != tc.want {
			t.Fatalf("%q: %q %v", tc.input, v, err)
		}
	}
}

// A minimal ELF fixture exercises .rodata extraction without executing PHP.
func writeELF(t *testing.T, path, version string) {
	t.Helper()
	names := []byte("\x00.shstrtab\x00.rodata\x00")
	data := []byte("X-Powered-By: PHP/" + version + "\x00")
	shoff := 64 + len(names) + len(data)
	b := make([]byte, shoff+3*64)
	copy(b, "\x7fELF\x02\x01\x01")
	put16 := func(off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
	put32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	put64 := func(off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }
	put16(16, 2)
	put16(18, 62)
	put32(20, 1)
	put64(40, uint64(shoff))
	put16(52, 64)
	put16(58, 64)
	put16(60, 3)
	put16(62, 1)
	copy(b[64:], names)
	copy(b[64+len(names):], data)
	put32(shoff+64, 1)
	put32(shoff+68, 3)
	put64(shoff+88, 64)
	put64(shoff+96, uint64(len(names)))
	put32(shoff+128, 11)
	put32(shoff+132, 1)
	put64(shoff+152, uint64(64+len(names)))
	put64(shoff+160, uint64(len(data)))
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func fixtureProcess(t *testing.T, root, pid, name, version string) {
	t.Helper()
	base := filepath.Join(root, pid)
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	binaryPath := filepath.Join(t.TempDir(), name)
	writeELF(t, binaryPath, version)
	if err := os.Symlink(binaryPath, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "stat"), []byte(pid+" (name with ) spaces) S "+strings.Repeat("0 ", 18)+"123"), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestHostDiscovery(t *testing.T) {
	root := t.TempDir()
	r, err := checkHost(context.Background(), root, nil)
	if err != nil || r.Status != NoPHP {
		t.Fatalf("%+v %v", r, err)
	}
	fixtureProcess(t, root, "100", "php-fpm8.3", "8.3.36")
	fixtureProcess(t, root, "200", "apache2", "8.3.35")
	base := filepath.Join(root, "200")
	if err := os.Mkdir(filepath.Join(base, "map_files"), 0700); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(t.TempDir(), "libphp.so")
	writeELF(t, module, "8.3.35")
	if err := os.Symlink(module, filepath.Join(base, "map_files", "1000-2000")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "maps"), []byte("1000-2000 r--p 0000 08:01 123 /old/libphp.so (deleted)\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err = checkHost(context.Background(), root, nil)
	if err != nil || len(r.Instances) != 2 || r.Status != PotentiallyVulnerable {
		t.Fatalf("%+v %v", r, err)
	}
	if r.Instances[0].Version != "8.3.36" || r.Instances[1].Version != "8.3.35" {
		t.Fatal(r)
	}
	// Failure to read Apache maps must never become "no PHP" or "safe".
	if err := os.Remove(filepath.Join(base, "maps")); err != nil {
		t.Fatal(err)
	}
	r, err = checkHost(context.Background(), root, nil)
	if err != nil || r.Status != Unknown || len(r.Warnings) == 0 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestRuntimeProbe(t *testing.T) {
	root := t.TempDir()
	fixtureProcess(t, root, "100", "php-fpm", "8.3.35")
	aliasProcess(t, root, "100", "101")
	token := strings.Repeat("t", 32)
	response := probeResult{PID: 101, StartTicks: "123", SAPI: "fpm-fcgi", Version: "8.3.35", RuntimeConfig: RuntimeConfig{str("0"), str("0"), str("-1")}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("missing token")
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()
	r, err := checkHost(context.Background(), root, []Probe{{server.URL, token}})
	if err != nil || r.Status != ConfigMitigated || len(r.Instances) != 1 || r.Instances[0].PID != 101 {
		t.Fatalf("%+v %v", r, err)
	}
	response.StartTicks = "999"
	r, err = checkHost(context.Background(), root, []Probe{{server.URL, token}})
	if err != nil || r.Status != PotentiallyVulnerable || len(r.Warnings) == 0 {
		t.Fatalf("%+v %v", r, err)
	}
	for _, address := range []string{"http://example.com/probe.php", "http://localhost/probe.php", "http://192.168.1.1/probe.php"} {
		if _, err := fetchProbe(context.Background(), Probe{address, token}); err == nil {
			t.Fatal("accepted nonliteral-loopback URL", address)
		}
	}
}

func aliasProcess(t *testing.T, root, original, pid string) {
	t.Helper()
	base := filepath.Join(root, pid)
	if err := os.MkdirAll(base, 0700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Readlink(filepath.Join(root, original, "exe"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(exe, filepath.Join(base, "exe")); err != nil {
		t.Fatal(err)
	}
	stat := pid + " (worker) S " + strings.Repeat("0 ", 18) + "123"
	if err := os.WriteFile(filepath.Join(base, "stat"), []byte(stat), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDeduplicatePaths(t *testing.T) {
	root := t.TempDir()
	fixtureProcess(t, root, "100", "php-fpm", "8.3.36")
	aliasProcess(t, root, "100", "101")
	// A different executable path, even with the same basename, is a separate installation.
	fixtureProcess(t, root, "200", "php-fpm", "8.3.35")
	fixtureProcess(t, root, "300", "apache2", "8.3.36")
	aliasProcess(t, root, "300", "301")
	module := filepath.Join(t.TempDir(), "libphp.so")
	writeELF(t, module, "8.3.36")
	for _, pid := range []string{"300", "301"} {
		base := filepath.Join(root, pid)
		if err := os.WriteFile(filepath.Join(base, "maps"), []byte("1000-2000 r--p 0000 08:01 123 /usr/lib/libphp.so\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	base := filepath.Join(root, "300", "map_files")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(module, filepath.Join(base, "1000-2000")); err != nil {
		t.Fatal(err)
	}
	// PID 301 has no readable module source: the duplicate must not be checked again.
	r, err := checkHost(context.Background(), root, nil)
	if err != nil || len(r.Instances) != 3 || len(r.Warnings) != 0 || r.Status != PotentiallyVulnerable {
		t.Fatalf("%+v %v", r, err)
	}
	for _, item := range r.Instances {
		if item.PID != 100 && item.PID != 200 && item.PID != 300 {
			t.Fatal("unexpected duplicate", item)
		}
	}
}
