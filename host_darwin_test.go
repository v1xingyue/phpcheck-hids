package phpcheck

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func machoFixture(version string) []byte {
	data := []byte("X-Powered-By: PHP/" + version + "\x00")
	b := make([]byte, 184+len(data))
	put32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
	put64 := func(off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }
	put32(0, 0xfeedfacf)
	put32(4, 0x100000c)
	put32(12, 2)
	put32(16, 1)
	put32(20, 152)
	put32(32, 0x19)
	put32(36, 152)
	copy(b[40:], "__TEXT")
	put64(64, uint64(len(b)))
	put64(80, uint64(len(b)))
	put32(96, 1)
	copy(b[104:], "__cstring")
	copy(b[120:], "__TEXT")
	put64(144, uint64(len(data)))
	put32(152, 184)
	copy(b[184:], data)
	return b
}

func TestDarwinFPMDiscovery(t *testing.T) {
	compiler, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable for native process fixture")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "main.c")
	path := filepath.Join(dir, "php-fpm")
	code := "#include <stdio.h>\n#include <unistd.h>\nint main(void) { puts(\"X-Powered-By: PHP/8.3.36\"); fflush(stdout); for (;;) pause(); }\n"
	if err := os.WriteFile(source, []byte(code), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, compiler, source, "-o", path).CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %s %v", output, err)
	}
	cmd := exec.CommandContext(ctx, path)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	r, err := scanHost(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range r.Instances {
		if item.Path == wantPath {
			if item.Status != VersionSafe || item.Version != "8.3.36" {
				t.Fatalf("incorrect native process assessment: %+v", item)
			}
			return
		}
	}
	t.Fatalf("native FPM fixture not discovered: %+v", r)
}

func TestUniversalMachOVersion(t *testing.T) {
	for _, version := range []string{"8.3.36", "8.3.35"} {
		first, second := machoFixture("8.3.36"), machoFixture(version)
		binary.LittleEndian.PutUint32(first[4:], 0x1000007)
		data := make([]byte, 48+len(first)+len(second))
		put := func(off int, value uint32) { binary.BigEndian.PutUint32(data[off:], value) }
		put(0, 0xcafebabe)
		put(4, 2)
		put(8, 0x1000007)
		put(16, 48)
		put(20, uint32(len(first)))
		put(28, 0x100000c)
		put(36, uint32(48+len(first)))
		put(40, uint32(len(second)))
		copy(data[48:], first)
		copy(data[48+len(first):], second)
		path := filepath.Join(t.TempDir(), "php-fpm")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		v, err := machOVersion(f)
		_ = f.Close()
		if version == "8.3.36" {
			if err != nil || v != version {
				t.Fatalf("%s %v", v, err)
			}
		} else if err == nil {
			t.Fatal("accepted conflicting universal slices")
		}
	}
}

func TestDarwinParsing(t *testing.T) {
	processes, err := parseDarwinProcesses(" 123 Fri Oct 23 08:00:00 2026     /opt/PHP  builds/php-fpm\n")
	if err != nil || len(processes) != 1 || processes[0].path != "/opt/PHP  builds/php-fpm" || processes[0].started != "Fri Oct 23 08:00:00 2026" {
		t.Fatalf("%+v %v", processes, err)
	}
	if _, err := parseDarwinProcesses("123 broken"); err == nil {
		t.Fatal("accepted malformed process output")
	}
	mappings := parseDarwinMappings("p123\nftxt\nD0x100\ni1234\nn/opt/PHP builds/libphp.so\nftxt\nD0x200\ni5678\nn/usr/lib/dyld\n")
	if len(mappings) != 2 || mappings[0].inode != "1234" || mappings[1].device != "0x200" {
		t.Fatal(mappings)
	}
}

func TestMappedMachOVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "php-fpm")
	if err := os.WriteFile(path, machoFixture("8.3.36"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	mapping := darwinMapping{path, strconv.FormatUint(stat.Ino, 10), fmt.Sprintf("0x%x", uint32(stat.Dev))}
	version, err := mappedMachOVersion(mapping)
	if err != nil || version != "8.3.36" {
		t.Fatalf("%s %v", version, err)
	}
	mapping.inode = "0"
	if _, err := mappedMachOVersion(mapping); err == nil {
		t.Fatal("accepted replaced mapped file")
	}
}

func TestDarwinProcessTools(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	output, err := macCommand(context.Background(), "/bin/ps", "-axo", "pid=,lstart=,comm=")
	if err != nil {
		t.Fatal(err)
	}
	processes, err := parseDarwinProcesses(string(output))
	found := false
	for _, process := range processes {
		if process.pid == os.Getpid() {
			found = true
		}
	}
	if err != nil || !found {
		t.Fatalf("%+v %v", processes, err)
	}
	output, err = macCommand(context.Background(), "/usr/sbin/lsof", "-nP", "-a", "-p", pid, "-d", "txt", "-F", "fDin")
	if err != nil {
		t.Fatal(err)
	}
	mappings := parseDarwinMappings(string(output))
	if len(mappings) == 0 || mappings[0].inode == "" || mappings[0].device == "" {
		t.Fatalf("invalid loaded-file evidence: %s", output)
	}
}
