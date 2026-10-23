package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/v1xingyue/phpcheck-hids"
)

func TestExitCode(t *testing.T) {
	for status, want := range map[phpcheck.Status]int{
		phpcheck.VersionSafe: 0, phpcheck.NoPHP: 0,
		phpcheck.PotentiallyVulnerable: 1, phpcheck.ConfigMitigated: 1,
		phpcheck.Unknown: 3, phpcheck.Status("unexpected"): 3,
	} {
		if got := exitCode(status); got != want {
			t.Errorf("%s: got %d want %d", status, got, want)
		}
	}
}

func TestArguments(t *testing.T) {
	t.Setenv("PHP_CHECK_TOKEN", "")
	for _, args := range [][]string{{"-invalid"}, {"unexpected"}, {"-probe"}, {"-probe", "http://127.0.0.1/probe.php"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("%v: code=%d stdout=%s stderr=%s", args, code, &stdout, &stderr)
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-h"}, &stdout, &stderr); code != 0 || !strings.Contains(stderr.String(), "-probe") {
		t.Fatalf("help: code=%d stderr=%s", code, &stderr)
	}
}
