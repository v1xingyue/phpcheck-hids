package phpcheck

import (
	"context"
	"debug/macho"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type darwinProcess struct {
	pid           int
	started, path string
}
type darwinMapping struct{ path, inode, device string }

func macCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd.Output()
}

func parseDarwinProcesses(output string) ([]darwinProcess, error) {
	var result []darwinProcess
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 7 {
			return nil, errors.New("incomplete macOS ps output")
		}
		pid, err := strconv.Atoi(fields[0])
		if err == nil && pid == 0 {
			continue
		} // kernel_task is not a PHP service.
		if err != nil || pid <= 0 {
			return nil, errors.New("invalid macOS process ID")
		}
		// Consume the fixed six columns without normalizing spaces inside the path.
		rest := strings.TrimSpace(line)
		for i := 0; i < 6; i++ {
			rest = strings.TrimLeft(rest[len(fields[i]):], " \t")
		}
		result = append(result, darwinProcess{pid, strings.Join(fields[1:6], " "), rest})
	}
	return result, nil
}

func parseDarwinMappings(output string) []darwinMapping {
	var result []darwinMapping
	var current darwinMapping
	for _, line := range strings.Split(output, "\n") {
		if line == "" {
			continue
		}
		switch line[0] {
		case 'f':
			current = darwinMapping{}
		case 'i':
			current.inode = line[1:]
		case 'D':
			current.device = line[1:]
		case 'n':
			current.path = line[1:]
			result = append(result, current)
		}
	}
	return result
}

func mappedMachOVersion(mapping darwinMapping) (string, error) {
	f, err := os.Open(mapping.path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	inode, e1 := strconv.ParseUint(mapping.inode, 10, 64)
	device, e2 := strconv.ParseUint(mapping.device, 0, 64)
	if !ok || e1 != nil || e2 != nil || stat.Ino != inode || uint64(uint32(stat.Dev)) != device {
		return "", errors.New("mapped file identity unavailable or differs from disk; worker may need restart")
	}
	return machOVersion(f)
}

func machOVersion(f *os.File) (string, error) {
	read := func(m *macho.File) (string, error) {
		section := m.Section("__cstring")
		if section == nil || section.Size > 32<<20 {
			return "", errors.New("missing or oversized Mach-O __cstring")
		}
		b, err := io.ReadAll(io.LimitReader(section.Open(), (32<<20)+1))
		if err != nil {
			return "", err
		}
		return extractVersion(b)
	}
	fat, err := macho.NewFatFile(f)
	if errors.Is(err, macho.ErrNotFat) {
		m, err := macho.NewFile(f)
		if err != nil {
			return "", err
		}
		return read(m)
	}
	if err != nil {
		return "", err
	}
	version := ""
	for _, arch := range fat.Arches {
		v, err := read(arch.File)
		if err != nil {
			return "", err
		}
		if version != "" && version != v {
			return "", errors.New("universal Mach-O slices have different PHP versions")
		}
		version = v
	}
	if version == "" {
		return "", errors.New("Mach-O contains no architecture")
	}
	return version, nil
}

func scanHost(ctx context.Context, probes []Probe) (Report, error) {
	r := Report{Status: Unknown, Instances: []Instance{}}
	output, err := macCommand(ctx, "/bin/ps", "-axo", "pid=,lstart=,comm=")
	if err != nil {
		return r, fmt.Errorf("macOS process discovery failed: %w", err)
	}
	processes, err := parseDarwinProcesses(string(output))
	if err != nil {
		return r, err
	}
	byPath := make(map[string]int)
	type identity struct {
		index   int
		started string
	}
	identities := make(map[int]identity)
	for _, process := range processes {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		name := filepath.Base(process.path)
		fpm := strings.HasPrefix(name, "php-fpm")
		if !fpm && name != "httpd" && name != "apache2" && !strings.HasPrefix(name, "httpd.") {
			continue
		}
		output, err := macCommand(ctx, "/usr/sbin/lsof", "-nP", "-a", "-p", strconv.Itoa(process.pid), "-d", "txt", "-F", "fDin")
		if err != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("pid %d: cannot read loaded files: %v", process.pid, err))
			continue
		}
		found := false
		for _, mapping := range parseDarwinMappings(string(output)) {
			name := filepath.Base(mapping.path)
			if (fpm && !strings.HasPrefix(name, "php-fpm")) || (!fpm && !phpModule(name)) {
				continue
			}
			found = true
			sapi := "apache2handler"
			if fpm {
				sapi = "fpm-fcgi"
			}
			key := sapi + "\x00" + mapping.path
			if index, exists := byPath[key]; exists {
				identities[process.pid] = identity{index, process.started}
				break
			}
			item := Instance{PID: process.pid, SAPI: sapi, Path: mapping.path, Status: Unknown}
			item.Version, err = mappedMachOVersion(mapping)
			if err != nil {
				item.Reason = "cannot verify loaded PHP build: " + err.Error()
			} else {
				evaluate(&item)
			}
			identities[process.pid] = identity{len(r.Instances), process.started}
			byPath[key] = len(r.Instances)
			r.Instances = append(r.Instances, item)
			break
		}
		if fpm && !found {
			r.Warnings = append(r.Warnings, fmt.Sprintf("pid %d: FPM executable not found among loaded files", process.pid))
		}
	}
	probed := make(map[int]bool)
	for _, probe := range probes {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		p, err := fetchProbe(ctx, probe)
		if err != nil {
			r.Warnings = append(r.Warnings, "runtime probe failed: "+err.Error())
			continue
		}
		identity, found := identities[p.PID]
		if !found || r.Instances[identity.index].SAPI != p.SAPI {
			r.Warnings = append(r.Warnings, "probe did not match a discovered macOS worker")
			continue
		}
		item := &r.Instances[identity.index]
		output, err := macCommand(ctx, "/bin/ps", "-p", strconv.Itoa(p.PID), "-o", "pid=,lstart=,comm=")
		var current []darwinProcess
		if err == nil {
			current, err = parseDarwinProcesses(string(output))
		}
		if err != nil || len(current) != 1 || current[0].started != identity.started {
			item.Status, item.Reason = Unknown, "process changed during runtime probe"
			continue
		}
		applyRuntimeProbe(item, p, probed[identity.index])
		probed[identity.index] = true
	}
	r.Status = aggregate(r.Instances, len(r.Warnings) != 0)
	return r, nil
}
