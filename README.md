# phpcheck-hids

[![CI and Release](https://github.com/v1xingyue/phpcheck-hids/actions/workflows/ci.yml/badge.svg)](https://github.com/v1xingyue/phpcheck-hids/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/v1xingyue/phpcheck-hids)](https://github.com/v1xingyue/phpcheck-hids/releases)

**用于 HIDS（主机入侵检测系统）的 Linux / macOS PHP 检测模块**，可嵌入 HIDS Agent 的 PHP 资产发现、漏洞风险评估和配置基线采集任务，也可作为独立命令行程序运行。

模块发现正在运行的 PHP-FPM 和 Apache mod_php，读取实际运行文件的 PHP 版本，按 PHP2Shell 的已知修复线评估风险；可选本机探针补充请求运行时配置。相同 SAPI、相同路径仅检查一次，适合将多 worker 服务汇总为一个 PHP 安装实例上报。

这是版本与配置评估模块，不检测入侵行为、不证明漏洞可利用，也不自动修复服务。`version_safe` 仅描述这两个 CVE 的上游版本门槛；`config_mitigated` 仅代表采样请求存在部分缓解措施，**不等于漏洞已修复或整台主机安全**。本项目为独立实现，不代表 PHP 或 OpenAI 官方。

入口：`CheckHost(ctx context.Context, probes []Probe) (Report, error)`，仅使用 Go 标准库，Go 1.22+。

本实现依据 2026-10-23 核对的上游规则，检查 CVE-2026-109618、CVE-2026-109619。

## 能力与运行条件

- Linux / macOS 本地检测，优先读取运行文件，避免把系统默认 CLI PHP 当成 Web PHP。
- 覆盖 PHP-FPM、Apache `apache2`/`httpd` 进程加载的常规 `libphp*.so` 模块。
- 同路径多进程只进行一次版本检测；不同安装路径分别上报。
- 返回结构化 JSON，包括路径、代表进程、版本、状态、配置证据和错误原因。
- 不执行目标 PHP 二进制、不发送漏洞利用请求、不改配置、不重启服务。
- Go 标准库实现，Release 二进制以 `CGO_ENABLED=0` 构建；Linux 为静态二进制。macOS 另外使用系统自带的 `/bin/ps`、`/usr/sbin/lsof`，并依赖正常的系统运行库。
- 应以 root 运行。Linux 需要访问目标 PID 命名空间的 `/proc`；macOS 需要读取目标进程的加载文件信息。容器 capability、LSM、`hidepid` 或 macOS 系统保护仍可能限制覆盖范围，见下文说明。

## 一键下载并执行

Linux 与 macOS 使用相同命令，自动识别系统和 CPU 架构：

```sh
curl -fsSL https://github.com/v1xingyue/phpcheck-hids/releases/latest/download/checking.sh | sh
```

为完整读取其他用户的服务进程，推荐在 root 会话中执行，或使用：

```sh
curl -fsSL https://github.com/v1xingyue/phpcheck-hids/releases/latest/download/checking.sh | sudo sh
```

传递检测器参数，例如查看帮助：

```sh
curl -fsSL https://github.com/v1xingyue/phpcheck-hids/releases/latest/download/checking.sh | sh -s -- -h
```

脚本先解析最新版本标签，再从同一版本下载匹配二进制与 `SHA256SUMS`；校验通过后执行，并在退出时清理临时目录。不会永久安装文件，也不会自行提权。扫描 JSON 写入 stdout，下载/执行提示写入 stderr；检测器退出码原样返回，下载或校验失败则返回 1，不执行二进制。依赖 `curl`、`uname`、`awk`、`mktemp` 以及 `sha256sum` 或 `shasum`。不支持的系统/架构会直接报错。

脚本通过当前进程架构选择产物；在 Rosetta 下可能选择 amd64 版本。校验清单与二进制来自同一 GitHub Release，校验用于完整性检查，不是独立签名认证。生产 HIDS 建议直接集成 Go 包或分发固定版本二进制，避免每次采集都联网下载。

## 准备私有下载执行库

`prepare-private.sh` 接收对外 URL 和静态目录，下载五个平台的二进制及 `checking.sh`，验证上游 SHA-256 后，生成适配私有 URL 的入口与新校验清单。私有 `checking.sh` 不访问 GitHub，不查询公网 latest；所有运行文件均从私有库的同一个固定版本目录获取。

先下载工具，再执行：

```sh
curl -fsSLO https://github.com/v1xingyue/phpcheck-hids/releases/latest/download/prepare-private.sh
sh prepare-private.sh \
  --url https://download.example.com/phpcheck \
  --static-dir /srv/www/phpcheck
```

也可直接用 curl 传参执行：

```sh
curl -fsSL https://github.com/v1xingyue/phpcheck-hids/releases/latest/download/prepare-private.sh | \
  sh -s -- --url https://download.example.com/phpcheck --static-dir /srv/www/phpcheck
```

| 参数 | 含义 |
|---|---|
| `--url` | 必填，静态目录对外的 HTTP(S) 根 URL，例如 `https://download.example.com/phpcheck` |
| `--static-dir` | 必填，Web 服务器映射到上述 URL 的本地目录，脚本会按需创建 |
| `--version` | 可选，固定上游版本，例如 `v0.3.0`；省略时只解析一次最新 Release |

URL 使用普通主机名/IPv4 和可选端口、路径；不接受 URL 凭据、查询参数、fragment 或 shell 特殊字符。工具依赖 POSIX Shell、curl、grep、awk、sed、mktemp 和 sha256sum/shasum，无需 Go、Python 或 GitHub CLI。准备机器需要能访问 GitHub Release；准备完成后，客户端只需要访问私有静态站点。

目录示例：

```text
/srv/www/phpcheck/
├── checking.sh                  # 对外一键入口，固定到下面的版本目录
└── releases/
    └── v0.3.0/
        ├── phpcheck-linux-386
        ├── phpcheck-linux-amd64
        ├── phpcheck-linux-arm64
        ├── phpcheck-darwin-amd64
        ├── phpcheck-darwin-arm64
        ├── checking.sh          # 与根入口内容相同，已写入私有 URL/版本
        └── SHA256SUMS           # 包括修改后的 checking.sh 的新校验值
```

把 `https://download.example.com/phpcheck/` 映射到 `/srv/www/phpcheck/` 后，客户端使用：

```sh
curl -fsSL https://download.example.com/phpcheck/checking.sh | sh
# 需要完整访问服务进程时：
curl -fsSL https://download.example.com/phpcheck/checking.sh | sudo sh
```

例如已有 Nginx HTTPS 站点可配置以下路径映射（按实际域名、目录和访问策略调整）：

```nginx
location /phpcheck/ {
    alias /srv/www/phpcheck/;
    autoindex off;
}
```

脚本不安装、不启动 HTTP 服务，也不修改 Nginx、证书、防火墙或鉴权。这里的“私有”是指自行托管；网络隔离与访问控制需由你的静态服务提供。目标目录应可由 Web 服务读取，避免放在无法遍历的私有家目录中。

发布新版本时再次运行准备脚本，使用新的 `--version` 或省略该参数以取最新版本。工具先暂存和校验全部文件，再发布不可变版本目录，最后原子切换根 `checking.sh`。失败不切换当前入口，旧版本目录保留，已经开始运行的客户端继续使用原版本。相同版本目录已存在时拒绝覆盖；更换 URL 或重建同版本时请使用新的静态目录。一个目录同一时刻只允许一个发布者；进程被强制终止后，如存在 `.prepare-private.lock`，应确认没有发布任务运行后再清理该锁目录。

## 下载 Release

[Release 下载页](https://github.com/v1xingyue/phpcheck-hids/releases/latest) 提供：

| 文件 | 目标系统/架构 |
|---|---|
| `phpcheck-linux-386` | Linux x86 32 位 |
| `phpcheck-linux-amd64` | Linux x86_64 / AMD64 / Intel 64 位 |
| `phpcheck-linux-arm64` | Linux ARM64 / AArch64 |
| `phpcheck-darwin-amd64` | macOS Intel 64 位 |
| `phpcheck-darwin-arm64` | macOS Apple Silicon |
| `checking.sh` | 自动下载、校验并执行的 POSIX Shell 脚本 |
| `prepare-private.sh` | 按 URL 和静态目录准备私有下载执行库 |
| `SHA256SUMS` | 五个二进制文件及两个脚本的 SHA-256 校验值 |

以 amd64 为例，先下载和核对，再执行：

```sh
curl -fLO https://github.com/v1xingyue/phpcheck-hids/releases/latest/download/phpcheck-linux-amd64
curl -fLO https://github.com/v1xingyue/phpcheck-hids/releases/latest/download/SHA256SUMS
grep '  phpcheck-linux-amd64$' SHA256SUMS | sha256sum -c -
chmod +x phpcheck-linux-amd64
sudo ./phpcheck-linux-amd64
```

Linux ARM64 将上面的 `amd64` 换成 `arm64`。macOS 使用对应的 `darwin` 文件，并用 `shasum -a 256 -c` 核对清单。macOS 产物从 v0.2.0 起提供，不包含 Apple Developer ID 签名或公证。一键入口从 v0.3.0 起改名为 `checking.sh`；旧版本的历史附件不修改。

## 在 HIDS Agent 中集成

### 方式一：直接调用 Go 包

```sh
go get github.com/v1xingyue/phpcheck-hids@v0.3.0
```

包名为 `phpcheck`。以下代码可作为 HIDS 采集任务的调用方式；调度和事件发送使用你已有 Agent 的实现：

```go
package collector

import (
    "context"
    "time"

    phpcheck "github.com/v1xingyue/phpcheck-hids"
)

func CollectPHP(parent context.Context) (phpcheck.Report, error) {
    ctx, cancel := context.WithTimeout(parent, 30*time.Second)
    defer cancel()
    return phpcheck.CheckHost(ctx, nil)
}
```

`nil` 表示不请求探针。这种模式适合默认的 HIDS 本地版本采集，无需在业务站点部署 PHP 文件。旧版本在没有供应商修复或配置证据时保守地报告 `potentially_vulnerable`。

HIDS 处理建议：

1. 将 `Report` 作为 PHP 风险评估事件上报，并由 Agent 添加自己的主机 ID、采集时间和容器/命名空间上下文；库不收集这些信息。
2. `error != nil` 时按采集失败处理，不能当成 `no_php` 或安全。只有成功完成可见范围的检测，`no_php` 才表示没有发现支持的运行服务。
3. 使用 `SAPI + Path` 作为同一主机、同一命名空间内的资产键。PID 只是代表/采样进程，不适合作为稳定资产 ID。
4. `version_safe` 可记录为对应规则通过；`config_mitigated` 应作为仍需升级的部分缓解；`unknown` 应保留原因；`potentially_vulnerable` 需结合发行版回移补丁核验，不应直接等价于已确认漏洞。
5. 每次调用重新发现当前进程（Linux 使用 `/proc`，macOS 使用 `ps`/`lsof`），只在本次调用内去重，不跨调用缓存。请由 HIDS 调度任务复用既有频率；在业务升级/重启后重新采集。库本身不会创建后台轮询或发网络告警。

### 方式二：作为子进程调用

非 Go 的 HIDS 可以执行 Release 二进制并读取 stdout JSON。用 stderr 诊断参数/输出错误，用退出码区分扫描执行结果；退出码 `1` 表示发现风险，不是程序崩溃。不要只用退出码 `0` 判断已找到且安全，`no_php` 也返回 `0`。

权限不足、无法读取运行文件、探针异常等情况会保留在 `warnings` 或实例的 `reason` 中。不要在 Agent 中丢弃这些字段。

## 命令行运行

在本目录为当前 Linux / macOS 系统编译并运行：

```sh
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o phpcheck ./cmd/phpcheck
sudo ./phpcheck
```

macOS 上交叉编译 Linux amd64 二进制：

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o phpcheck-linux-amd64 ./cmd/phpcheck
```

上述命令移除符号表和 DWARF 调试信息，并去除本地源码路径。使用 Go 1.24.4 实测，Linux amd64 二进制由约 9.0 MiB 缩小到 6.1 MiB，功能不变；代价是调试器定位更困难。Go 运行时和网络、JSON、ELF 处理的标准库代码仍需随二进制携带。

配置探针后可用 `-probe`，支持重复指定多个本机端点：

```sh
# 在目标 Linux 主机执行；输入与 probe.php 一致的 token。
read -r -s PHP_CHECK_TOKEN
export PHP_CHECK_TOKEN
sudo --preserve-env=PHP_CHECK_TOKEN ./phpcheck \
  -probe http://127.0.0.1:8080/internal/phpcheck.php
unset PHP_CHECK_TOKEN
```

固定 30 秒检测超时。标准输出为 JSON；参数错误写入标准错误。退出码：`0`=版本安全或未发现 PHP（通过 JSON 的 status 区分），`1`=疑似受影响或仅配置缓解，`2`=参数/执行/输出失败，`3`=状态未知。配置缓解不会以安全退出码返回。`-h` 查看帮助。

## 调用

推荐通过 `go get` 导入整个包；如需复制源码，须包含 `checker.go` 和所有 `host_*.go` 平台文件。入口自动选择当前系统的发现方式：

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

report, err := phpcheck.CheckHost(ctx, nil)
if err != nil {
    // 检测失败，不等同于没有 PHP，也不等同于安全。
    return err
}
data, err := json.MarshalIndent(report, "", "  ")
if err != nil {
    return err
}
fmt.Println(string(data))
```

无探针时仍检查运行版本。旧版实例的配置为未确认，结果是 `potentially_vulnerable`，不是已证实可利用。

要读取实际请求的配置，将 `probe.php` 接入已有服务的目标 FPM 池或 Apache 虚拟主机，仅允许本机访问。将文件中的占位 token 替换为随机 token（至少 32 字符，例如 `openssl rand -hex 32`），并在 Web 服务器转发 `Authorization` 请求头。不要用 CLI PHP 或 `php -S` 执行探针，那不是目标运行环境。PHP 5.4 因缺少 `hash_equals` 会拒绝探测。

```go
report, err := phpcheck.CheckHost(ctx, []phpcheck.Probe{
    {
        URL: "http://127.0.0.1:8080/internal/phpcheck.php",
        Token: token, // 和 probe.php 一致，从你的凭据配置读取。
    },
})
```

端口、路径按你的部署调整。只接受 HTTP 字面量回环地址；拒绝 DNS 主机名、代理、重定向。必须通过目标服务自身执行探针；如有反向代理，仍须在边缘限制该路径访问。请避免自动前置脚本或应用代码在探针运行前修改配置。探针按 PID、进程启动时间、SAPI、版本与本地发现结果匹配；不匹配会告警。探测结束可删除 PHP 文件。

## 返回值

| status | 含义 |
|---|---|
| `version_safe` | 运行文件内的版本达到已知上游修复版本；只针对这两个 CVE |
| `config_mitigated` | 旧版本的被采样请求观察到 progress 主/局部值均关闭，且 memory_limit=-1；仅部分缓解 |
| `potentially_vulnerable` | 低于上游修复线，未确认两个缓解设置；未核验供应商回移补丁 |
| `unknown` | 版本无法识别、预发布/未知分支、进程读取失败或覆盖范围不完整 |
| `no_php` | 可见范围内未发现运行中的 PHP-FPM 或加载 libphp 的 Apache |

按 SAPI 和路径去重：同一路径的 FPM 可执行文件或 Apache PHP 模块只检查一次、返回一条 `Instance`。不同路径分别检查；`(deleted)` 标记保留，避免将尚未重启的旧文件与新文件合并。每个 `Instance` 含代表进程 PID、SAPI、文件路径、版本、配置证据和原因；探针可以匹配同路径任意已发现的 worker，匹配后 PID 为对应采样进程。主机结果取最保守结果：疑似受影响 > 未知 > 配置缓解 > 版本安全 > 未发现。

特别注意：路径级结果使用代表进程/请求采样。同路径可能有多个 FPM 池和不同配置，因此 `config_mitigated` 仅说明采样请求符合缓解条件，不代表该路径下所有 worker 或站点配置一致。多个显式探针仍分别请求，同路径的探针结果取最保守值，但只输出一条结果。这不是全站配置合规审计。

### JSON 字段

| 对象/字段 | 含义 |
|---|---|
| `status` | 主机可见范围内的总体状态 |
| `instances` | 按 SAPI/路径去重的检测结果数组；未发现时为空数组 |
| `warnings` | 可选，覆盖不完整或探针失败等诊断 |
| `instances[].pid` / `start_ticks` | 代表或采样进程的 PID；Linux 为启动 tick，macOS 的 start_ticks 为空，内部使用 ps 的启动时间校验 |
| `instances[].sapi` | `fpm-fcgi` 或 `apache2handler` |
| `instances[].path` | 运行可执行文件或加载模块的路径 |
| `instances[].version` | 可选，从运行文件或匹配的本机探针读取的 PHP 版本 |
| `instances[].status` / `reason` | 该路径的判定与具体原因 |
| `instances[].config` | 可选，仅存在于获得匹配的运行时探针响应时 |
| `config.progress` / `progress_master` | progress 的请求局部值与主值；字段为 null 时表示指令缺失 |
| `config.memory_limit` | 请求运行时的 memory_limit 字符串；null 表示缺失 |

例如，在完成检测且没有发现支持的运行服务时：

```json
{
  "status": "no_php",
  "instances": []
}
```

`no_php` 不代表磁盘上没有安装 PHP，也不代表无法访问的容器里没有 PHP。

## 规则与边界

- 上游修复线：8.2.35、8.3.36、8.4.27、8.5.12。同分支逐个数值比较，未知新分支不自动判安全。
- PHP 5.4–5.6、7.0–7.4、8.0–8.1 按上游规则标记疑似受影响。发行版可能已回移修复，所以“版本旧”不代表确定存在漏洞。
- `session.upload_progress.enabled=0` 与 `memory_limit=-1` 只降低特定攻击路径的风险，不是完整修复。PHP 8.5 还有 `fatal_error_backtraces` 等路径；两个设置不覆盖全部风险。
- memory_limit=-1 取消 PHP 自身内存限制，可能增加主机内存耗尽风险。生产环境应另有容器/cgroup 内存边界；此函数不修改任何配置。
- 从 FPM 的 `/proc/PID/exe`、Apache 的 `/proc/PID/map_files` 读取实际加载的 ELF 文件，提取 PHP 编译进去的版本常量；不会使用可能已被替换的磁盘路径，也不会调用 CLI PHP 代替 Web PHP。特殊构建缺少常量时返回未知，可由运行时探针补充。
- Apache 的 `map_files` 读取可能需要额外 capability，即使 root 也可能受容器、内核或安全策略限制；失败返回未知。
- macOS 从 `ps` 发现服务、从 `lsof` 读取已加载的文本文件；比较加载文件与磁盘文件的设备号和 inode 后，解析 Mach-O `__cstring` 中的版本常量。磁盘文件已替换、无法读取或 Universal Binary 两个 slice 的版本不同，返回未知；不会启动目标 PHP 二进制来猜版本。
- macOS 探针按 PID、SAPI 和版本匹配；请求前后用 `ps` 的启动时间确认 worker 未变化。PHP 探针在 macOS 上不依赖 `/proc`。macOS 保护策略可能阻止加载文件枚举，失败会保留诊断信息。
- 以 root 运行，并确保能完整读取目标进程。Linux 范围仅为当前可见 PID 命名空间；不递归进入容器，不支持 Windows，不涵盖 CGI、LiteSpeed、FrankenPHP、重命名进程或重命名 libphp 模块，也不以安装包存在判定服务正在运行。`no_php` 的含义仅限上述范围。
- 没有实现发行版回移补丁识别、任意 php.ini/FPM/Apache 配置解析、全站请求上下文枚举或利用探测。磁盘配置不能证明旧 worker 已应用修改，因此不用它推断运行时安全。

## 验证

```sh
go test ./...
go vet ./...
GOOS=linux GOARCH=amd64 go test -c -o /tmp/phpcheck.test
```

测试涵盖修复边界、配置组合、多实例聚合、模拟 `/proc`/ELF 的 FPM 与 Apache 发现、路径去重和本机探针身份匹配；macOS 另测试实际 ps/lsof 调用、原生模拟 FPM 进程发现、Mach-O/Universal Binary 版本解析及文件身份不匹配。一键脚本测试覆盖五种目标、参数/退出码透传、不支持的平台、校验失败拒绝执行和临时文件清理。原生 FPM 夹具不是 PHP，尚未进行真实 PHP-FPM/Apache 服务的端到端集成测试。

## CI/CD 与发布

工作流位于 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)：

1. 推送 `main`、提交 Pull Request 或手动触发：在 Linux amd64、macOS Intel、macOS ARM64 分别检查 gofmt、运行 `go vet`、`go test -race ./...` 和脚本语法检查。
2. 测试成功后，以 `CGO_ENABLED=0`、`-trimpath`、`-ldflags='-s -w'` 并行构建 Linux `386`/`amd64`/`arm64` 和 macOS `amd64`/`arm64`，上传 Actions artifacts。
3. 推送 `vMAJOR.MINOR.PATCH` 标签：五种目标全部构建成功后，计算 SHA-256 并创建 GitHub Release，上传五个二进制、`checking.sh`、`prepare-private.sh` 和 `SHA256SUMS`。

仅发布 job 有 `contents: write` 权限；测试和构建 job 为只读。工作流使用 GitHub 自带 `GITHUB_TOKEN`，不需要额外配置 PAT。官方 Actions 固定到提交 SHA，更新版本时需同步更新这些 SHA。

维护者发布示例：

```sh
git tag v0.3.0
git push origin v0.3.0
```

请在发布前确认 README 的版本规则仍符合 PHP 官方和目标供应商公告。工作流使用 Go 当前稳定版构建；`go.mod` 声明源码最低 Go 1.22，CI 不覆盖所有旧工具链。Linux amd64 和两个 macOS 目标会运行本机 CLI 帮助验证；Linux 386/arm64 是交叉编译产物，不代表已完成对应硬件或真实 PHP 服务集成测试。

## 目录

```text
checker.go                 Go 包与检测入口
host_*.go                  Linux / macOS 平台发现与解析
checker_test.go            规则、进程发现、路径去重和探针测试
cmd/phpcheck/main.go       命令行入口
cmd/phpcheck/main_test.go  参数与退出码测试
probe.php                  可选的本机 PHP 配置采样端点
checking.sh                按当前系统/架构下载、校验并执行
checking_test.go           下载脚本离线验证
prepare-private.sh        下载并准备私有静态库
private_mirror_test.go     私有 URL、重算校验和失败保留旧版本验证
.github/workflows/ci.yml   测试、跨架构编译与 Release 发布
LICENSE / NOTICE           Apache-2.0 许可证与来源说明
```

## 许可证

[Apache License 2.0](LICENSE)。版本分类规则参考上游 `openai/php2shell-checker`，来源与版本快照见 [NOTICE](NOTICE)。仓库不包含上游利用代码，也不进行利用验证。

## 来源

- [原仓库的版本规则](https://github.com/openai/php2shell-checker/blob/ffcd3fc82e5b404f2a04a95b2805ca7639d530fa/skills/phpcheck-url/scripts/phpcheck.js)
- [原仓库关于运行实例、供应商补丁和重启的说明](https://github.com/openai/php2shell-checker/blob/ffcd3fc82e5b404f2a04a95b2805ca7639d530fa/skills/phpcheck-server/SKILL.md)
- [PHP 官方公告：修复版本与不完整缓解措施](https://www.php.net/archive/2026.php#2026-10-21-5)
- [PHP 源码中的版本头常量](https://github.com/php/php-src/blob/PHP-8.3/main/SAPI.h)
