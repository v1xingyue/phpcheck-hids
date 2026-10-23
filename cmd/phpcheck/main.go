package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/v1xingyue/phpcheck-hids"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("phpcheck", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var probes []phpcheck.Probe
	flags.Func("probe", "本机 PHP 探针 URL，可重复指定；token 从 PHP_CHECK_TOKEN 环境变量读取", func(address string) error {
		probes = append(probes, phpcheck.Probe{URL: address})
		return nil
	})
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "不接受位置参数，使用 -h 查看用法")
		return 2
	}
	if len(probes) > 0 {
		token := os.Getenv("PHP_CHECK_TOKEN")
		if len(token) < 32 {
			fmt.Fprintln(stderr, "使用 -probe 时，PHP_CHECK_TOKEN 至少需要 32 个字符")
			return 2
		}
		for i := range probes {
			probes[i].Token = token
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	report, err := phpcheck.CheckHost(ctx, probes)
	if err != nil {
		report.Status = phpcheck.Unknown
		report.Warnings = append(report.Warnings, err.Error())
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if writeErr := encoder.Encode(report); writeErr != nil {
		fmt.Fprintln(stderr, "输出检测结果失败:", writeErr)
		return 2
	}
	if err != nil {
		return 2
	}
	return exitCode(report.Status)
}

func exitCode(status phpcheck.Status) int {
	switch status {
	case phpcheck.VersionSafe, phpcheck.NoPHP:
		return 0
	case phpcheck.PotentiallyVulnerable, phpcheck.ConfigMitigated:
		return 1
	default:
		return 3
	}
}
