// Package phpcheck checks PHP2Shell version thresholds and observed mitigations.
package phpcheck

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Status string

const (
	VersionSafe           Status = "version_safe"
	ConfigMitigated       Status = "config_mitigated" // Partial mitigation, NOT a complete fix.
	PotentiallyVulnerable Status = "potentially_vulnerable"
	Unknown               Status = "unknown"
	NoPHP                 Status = "no_php"
)

type Instance struct {
	PID        int            `json:"pid"`
	StartTicks string         `json:"start_ticks"`
	SAPI       string         `json:"sapi"`
	Path       string         `json:"path"`
	Version    string         `json:"version,omitempty"`
	Status     Status         `json:"status"`
	Config     *RuntimeConfig `json:"config,omitempty"`
	Reason     string         `json:"reason"`
}

type RuntimeConfig struct {
	Progress       *string `json:"progress"`
	ProgressMaster *string `json:"progress_master"`
	MemoryLimit    *string `json:"memory_limit"`
}

type Report struct {
	Status    Status     `json:"status"`
	Instances []Instance `json:"instances"`
	Warnings  []string   `json:"warnings,omitempty"`
}

// Probe is an existing PHP endpoint served by the target FPM pool or Apache vhost.
// It must be restricted to loopback and use probe.php's token authentication.
type Probe struct{ URL, Token string }

type probeResult struct {
	PID        int    `json:"pid"`
	StartTicks string `json:"start_ticks"`
	SAPI       string `json:"sapi"`
	Version    string `json:"version"`
	RuntimeConfig
}

// CheckHost inspects running PHP-FPM processes and Apache's loaded libphp modules.
// Each SAPI/path is checked once; PID identifies the representative/sample process.
// Run as root in the target Linux PID namespace. An error is not "no PHP".
// A probe covers only its responding worker/request, not every pool/vhost.
func CheckHost(ctx context.Context, probes []Probe) (Report, error) {
	if runtime.GOOS != "linux" {
		return Report{Status: Unknown}, errors.New("CheckHost requires Linux /proc")
	}
	r, err := checkHost(ctx, "/proc", probes)
	if os.Geteuid() != 0 {
		r.Warnings = append(r.Warnings, "not running as root; other users' processes may be hidden")
		r.Status = aggregate(r.Instances, true)
	}
	return r, err
}

func checkHost(ctx context.Context, proc string, probes []Probe) (Report, error) {
	r := Report{Status: Unknown, Instances: []Instance{}}
	entries, err := os.ReadDir(proc)
	if err != nil {
		return r, err
	}
	byPath := make(map[string]int)
	type processIdentity struct {
		index int
		ticks string
	}
	processes := make(map[int]processIdentity)
	readVersion := func(path string) (string, error) {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		return elfVersion(f)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}
		base := filepath.Join(proc, entry.Name())
		exe, err := os.Readlink(filepath.Join(base, "exe"))
		if err != nil {
			if !os.IsNotExist(err) {
				r.Warnings = append(r.Warnings, fmt.Sprintf("pid %d: cannot read exe: %v", pid, err))
			}
			continue // Kernel threads and processes that exited have no exe.
		}
		name := filepath.Base(strings.TrimSuffix(exe, " (deleted)"))
		sapi, source, path := "", "", exe
		switch {
		case strings.HasPrefix(name, "php-fpm"):
			sapi, source = "fpm-fcgi", filepath.Join(base, "exe")
		case name == "apache2" || name == "httpd" || strings.HasPrefix(name, "httpd."):
			maps, err := os.ReadFile(filepath.Join(base, "maps"))
			if err != nil {
				r.Warnings = append(r.Warnings, fmt.Sprintf("pid %d: cannot read Apache maps: %v", pid, err))
				continue
			}
			for _, line := range strings.Split(string(maps), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 6 {
					continue
				}
				p := strings.Join(fields[5:], " ")
				if phpModule(filepath.Base(strings.TrimSuffix(p, " (deleted)"))) {
					sapi, path = "apache2handler", p
					// map_files points at the actual mapped inode, including deleted modules.
					source = filepath.Join(base, "map_files", fields[0])
					break
				}
			}
		}
		if sapi == "" {
			continue
		}
		item := Instance{PID: pid, SAPI: sapi, Path: path, Status: Unknown}
		stat, err := os.ReadFile(filepath.Join(base, "stat"))
		if err == nil {
			item.StartTicks, err = startTicks(string(stat))
		}
		// shortcut: one sample per SAPI/path may span pools with different settings; use per-pool detection when required.
		key := sapi + "\x00" + path
		if index, exists := byPath[key]; exists {
			processes[pid] = processIdentity{index, item.StartTicks}
			continue
		}
		byPath[key] = len(r.Instances)
		processes[pid] = processIdentity{len(r.Instances), item.StartTicks}
		if err != nil {
			item.Reason = "cannot establish process identity: " + err.Error()
		} else {
			item.Version, err = readVersion(source)
			if err != nil {
				item.Reason = "cannot read running PHP build: " + err.Error()
			} else {
				evaluate(&item)
			}
		}
		r.Instances = append(r.Instances, item)
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
		identity, found := processes[p.PID]
		if !found || identity.ticks == "" || identity.ticks != p.StartTicks || r.Instances[identity.index].SAPI != p.SAPI {
			r.Warnings = append(r.Warnings, "probe did not match a discovered worker; check PID namespace and permissions")
			continue
		}
		i := identity.index
		item := &r.Instances[i]
		// The process may have exited or its PID been reused during the HTTP request.
		stat, err := os.ReadFile(filepath.Join(proc, strconv.Itoa(p.PID), "stat"))
		var ticks string
		if err == nil {
			ticks, err = startTicks(string(stat))
		}
		if err != nil || ticks != identity.ticks {
			item.Status, item.Reason = Unknown, "process changed during runtime probe"
			continue
		}
		if item.Version != "" && item.Version != p.Version {
			item.Status, item.Reason = Unknown, "runtime probe and loaded build versions disagree"
			continue
		}
		candidate := *item
		candidate.PID, candidate.StartTicks = p.PID, p.StartTicks
		candidate.Version, candidate.Config = p.Version, &p.RuntimeConfig
		evaluate(&candidate)
		// Keep the least reassuring result when multiple probes cover one path.
		if !probed[i] || aggregate([]Instance{*item, candidate}, false) == candidate.Status {
			*item = candidate
		}
		probed[i] = true
	}
	r.Status = aggregate(r.Instances, len(r.Warnings) != 0)
	return r, nil
}

func phpModule(name string) bool {
	return strings.HasPrefix(name, "libphp") && (strings.HasSuffix(name, ".so") || strings.Contains(name, ".so."))
}

func startTicks(stat string) (string, error) {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return "", errors.New("invalid proc stat")
	}
	fields := strings.Fields(stat[end+1:])
	if len(fields) < 20 {
		return "", errors.New("incomplete proc stat")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", err
	}
	return fields[19], nil // Field 22; comm may itself contain spaces/parentheses.
}

var buildVersion = regexp.MustCompile(`X-Powered-By: PHP/([^\x00\r\n ]{1,96})\x00`)

func elfVersion(f *os.File) (string, error) {
	e, err := elf.NewFile(f)
	if err != nil {
		return "", err
	}
	section := e.Section(".rodata")
	if section == nil || section.Size > 32<<20 {
		return "", errors.New("missing or oversized ELF .rodata")
	}
	b, err := io.ReadAll(io.LimitReader(section.Open(), (32<<20)+1))
	if err != nil {
		return "", err
	}
	return extractVersion(b)
}

func extractVersion(b []byte) (string, error) {
	version := ""
	for _, match := range buildVersion.FindAllSubmatch(b, -1) {
		candidate := string(match[1])
		if version != "" && version != candidate {
			return "", errors.New("conflicting embedded PHP versions")
		}
		version = candidate
	}
	if version == "" {
		return "", errors.New("embedded PHP version missing; use runtime probe")
	}
	return version, nil
}

var versionPattern = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)([-+~].*)?$`)
var prerelease = regexp.MustCompile(`(?i)(^|[-+~.])(dev|alpha|beta|rc)`)

// versionStatus mirrors upstream's explicit branch table, not lexical comparison.
func versionStatus(version string) Status {
	m := versionPattern.FindStringSubmatch(version)
	if m == nil || prerelease.MatchString(m[4]) {
		return Unknown
	}
	major, e1 := strconv.Atoi(m[1])
	minor, e2 := strconv.Atoi(m[2])
	patch, e3 := strconv.Atoi(m[3])
	if e1 != nil || e2 != nil || e3 != nil {
		return Unknown
	}
	if (major == 5 && minor >= 4 && minor <= 6) || (major == 7 && minor <= 4) || (major == 8 && minor <= 1) {
		return PotentiallyVulnerable
	}
	if major != 8 {
		return Unknown
	}
	fixed, ok := map[int]int{2: 35, 3: 36, 4: 27, 5: 12}[minor]
	if !ok {
		return Unknown
	}
	if patch >= fixed {
		return VersionSafe
	}
	return PotentiallyVulnerable
}

func evaluate(i *Instance) {
	i.Status = versionStatus(i.Version)
	switch i.Status {
	case VersionSafe:
		i.Reason = "running build meets upstream fix for both CVEs; version-based assessment"
	case Unknown:
		i.Reason = "unrecognized version/branch or prerelease"
	case PotentiallyVulnerable:
		i.Reason = "below upstream fix; vendor backports not assessed; runtime mitigation not confirmed"
		if i.Config == nil {
			return
		}
		c := i.Config
		if c.Progress == nil || c.ProgressMaster == nil || c.MemoryLimit == nil {
			i.Reason = "runtime configuration incomplete; cannot confirm mitigation"
			return
		}
		if iniOff(*c.Progress) && iniOff(*c.ProgressMaster) && strings.TrimSpace(*c.MemoryLimit) == "-1" {
			i.Status, i.Reason = ConfigMitigated, "sampled request has progress disabled (master/local) and memory_limit=-1; partial mitigation only, other contexts unverified"
		} else {
			i.Reason = "sampled request does not meet both mitigation checks; vendor backports not assessed"
		}
	}
}

func iniOff(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "off", "false", "no":
		return true
	}
	return false
}

func aggregate(items []Instance, incomplete bool) Status {
	result := NoPHP
	if incomplete {
		result = Unknown
	}
	rank := map[Status]int{NoPHP: 0, VersionSafe: 1, ConfigMitigated: 2, Unknown: 3, PotentiallyVulnerable: 4}
	for _, item := range items {
		if rank[item.Status] > rank[result] {
			result = item.Status
		}
	}
	return result
}

func fetchProbe(ctx context.Context, p Probe) (probeResult, error) {
	var result probeResult
	u, err := url.Parse(p.URL)
	if err != nil {
		return result, errors.New("invalid probe URL")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.User != nil || u.Fragment != "" || len(p.Token) < 32 {
		return result, errors.New("probe requires http://loopback-IP URL and token of at least 32 characters")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return result, err
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 5 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("probe redirects prohibited") }}
	resp, err := client.Do(req)
	if err != nil {
		return result, errors.New("local probe request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("probe returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8193))
	if err != nil {
		return result, err
	}
	if len(b) > 8192 {
		return result, errors.New("probe response exceeds 8 KiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return result, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return result, errors.New("unexpected trailing probe response")
	}
	if result.PID <= 0 || result.StartTicks == "" || result.Version == "" || (result.SAPI != "fpm-fcgi" && result.SAPI != "apache2handler") {
		return result, errors.New("incomplete or unsupported runtime probe")
	}
	return result, nil
}
