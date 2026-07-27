# DNS client architecture（q v0.19.12）

## 边界

- 仅 full `nexttrace` 编译 `internal/dnsclient`；入口固定为首参数 `-l`/`--dns`。
- DNS 模式是独占终端模式，不进入 Web、MCP、`internal/service`，不替换现有 resolver。
- 直接依赖 `github.com/natesales/q v0.19.12` 的公开 `cli`、`transport`、`output`、`util`、`util/tls` 子包。
- 没有修改上游、fork、`replace`、vendor、`go:linkname` 或 companion executable，也没有复制 q root 源文件。

## 本地编排对应关系

代码行数快照：2026-07-27，adapter code commit `7a2f2bc`，基于 `origin/main` `0bcc549`。

| q root 职责 | NextTrace adapter | 生产代码行数 |
| --- | --- | ---: |
| qrc/env、flags、位置参数、RR type、IDNA、reverse/CHAOS | `config.go` | 387 |
| DNS header、EDNS、DNSSEC、NSID、ECS、padding、cookie | `query.go` | 138 |
| DNS Stamp、server URL、协议、默认端口 | `server.go` | 290 |
| TLS 配置及 UDP/TCP/DoT/DoH/DoQ/ODoH/DNSCrypt factory | `transport.go` | 369 |
| 多服务器、timeout、ID check、PTR、输出调度 | `runner.go` + `output.go` | 645 |
| recursive AXFR | `xfr.go` | 253 |
| flavor/CLI 接线 | `cmd/dns_mode*.go` | 98 |
| **合计** |  | **2,180** |

q v0.19.12 的 `main.go`、`resolver.go`、`xfr.go` 合计 1,001 行。本 adapter 为避免 q root 的全局状态、超时竞态、路径穿越和可预判 fatal 路径，额外维护 1,179 行。

## 依赖与体积

测量快照：2026-07-27，Darwin/arm64，`go build -trimpath -ldflags '-s -w'`；adapter code commit `7a2f2bc` 对比 `origin/main` `0bcc549`。

| flavor | 基线 bytes | 集成后 bytes | 增量 | 增幅 |
| --- | ---: | ---: | ---: | ---: |
| nexttrace | 26,999,186 | 30,359,186 | 3,360,000（3.204 MiB） | 12.44% |
| nexttrace-tiny | 11,050,210 | 11,083,234 | 33,024（0.031 MiB） | 0.30% |
| ntr | 11,050,210 | 11,083,234 | 33,024（0.031 MiB） | 0.30% |

- 按 `go list -deps .` 口径，full 编译依赖包数从 425 增至 483（+58）；链接 q 的 5 个公开包。
- tiny/ntr 编译依赖包数从 301 变为 300，`go list -deps` 与 `go version -m` 均无 `github.com/natesales/q`。其 33,024 bytes 变化来自 Go module 的全局版本选择，不是链接 q。
- 完整 Go module graph 从 105 增至 193（+88，包含上游测试/工具依赖，不等同于链接包）。
- 许可证审计以锁定版本的根 `LICENSE`/`NOTICE`，以及 Darwin/arm64、Linux/amd64、Windows/amd64 full 二进制的 `go version -m` 基线差分为准。新增实际链接模块如下；锁定版本见 `go.mod`/`go.sum`。

| 许可证 | 新增实际链接模块 |
| --- | --- |
| Unlicense | `github.com/AdguardTeam/golibs`、`github.com/ameshkov/dnscrypt/v2`、`github.com/ameshkov/dnsstamps` |
| MIT | `github.com/aymanbagabas/go-osc52/v2`、`github.com/charmbracelet/colorprofile`、`github.com/charmbracelet/lipgloss`、`github.com/charmbracelet/log`、`github.com/charmbracelet/x/ansi`、`github.com/charmbracelet/x/cellbuf`、`github.com/charmbracelet/x/term`、`github.com/clipperhouse/displaywidth`、`github.com/go-logfmt/logfmt`、`github.com/jedisct1/go-dnsstamps`、`github.com/json-iterator/go`、`github.com/lucasb-eyer/go-colorful`、`github.com/muesli/termenv`、`github.com/rivo/uniseg`、`github.com/sthorne/odoh-go`、`github.com/xo/terminfo` |
| BSD-2-Clause | `github.com/cisco/go-hpke`、`github.com/cisco/go-tls-syntax` |
| BSD-3-Clause | `github.com/cloudflare/circl`、`github.com/jessevdk/go-flags`、`github.com/miekg/dns`、`golang.org/x/exp` |
| Apache-2.0 | `github.com/modern-go/concurrent`、`github.com/modern-go/reflect2` |
| GPL-3.0 | `github.com/natesales/bgptools-go`、`github.com/natesales/q` |
| MIT AND Apache-2.0 | `gopkg.in/yaml.v3`（文件级双许可） |

- q 根许可证为 GPL-3.0；其 `transport` 目录另保留 Apache-2.0 与 MIT 派生代码告知，不表示 q 整体可在三者间任选。`github.com/clipperhouse/uax29/v2` 与 `google.golang.org/protobuf` 仅版本升级，许可证仍分别为 MIT、BSD-3-Clause。新增但只用于测试/工具链的 `golang.org/x/mod`、`golang.org/x/tools` 均为 BSD-3-Clause，不链接进发布二进制。

## 已验证语义

- q `cli.Flags` 的字段名、字段类型和完整 struct tags 有 v0.19.12 反射快照；description 中的 default-true 语义也受门禁保护。
- qrc、`Q_DEFAULT_SERVER`、`NO_COLOR`、`SSLKEYLOGFILE`、shell completion、位置参数、默认 RR types、IDNA、reverse、CHAOS。
- DNS header、DNSSEC/EDNS、NSID、ECS、padding、cookie、TCP fallback、TXT concat、TTL rounding、PTR cache、recursive AXFR 及取消后的连接关闭/drain。
- 本地 UDP、TCP、DoT、DoH、DoQ、ODoH、DNSCrypt 服务；各 transport 的参数映射有字段断言。
- pretty、column、raw、JSON、YAML 与官方 q v0.19.12 同语料的 stdout/stderr/退出码差分；语料还覆盖 verbose/trace、qrc/env、completion、多服务器、DNS Stamp、全部 transport、HTTP header、TLS key log、numeric RR、userinfo、parser error 和 recursive AXFR。
- q logger、颜色、默认 resolver、HTTP default transport 的作用域恢复有回归测试。
- q output 与 DNSCrypt 残留 `log.Fatal` 通过子进程测试；adapter 自有 version/AXFR 写入错误返回普通 error。

## 验证状态

- `go test ./...`、`go test -tags flavor_tiny ./...`、`go test -tags flavor_ntr ./...`、`go vet ./...`、Node Web 13 项测试通过。
- `go test -race ./internal/dnsclient ./cmd` 通过。全仓 race 仅在未修改的 `wshandle` 发现数据竞争；同一竞争已在 `origin/main` 快照复现，因此不归因于本次集成，也未越界修复。
- 官方 q v0.19.12 差分语料全部通过。
- 发布矩阵共 32 个目标、3 个 flavor：31 个本机可用目标的 93 次构建通过；62 个 tiny/ntr 产物均不含 q，31 个 full 产物均含 q v0.19.12；12 个选定 Linux 产物的 UPX 压缩通过。
- Android arm64 的 3 个 `CGO_ENABLED=1` 构建因本机缺 NDK r26d clang 未执行成功；补充 `CGO_ENABLED=0` 三 flavor 均通过，正式 PR 仍须由 CI 完成 NDK 验证。

## 与 q root 的已知语义差异

- recursive AXFR 使用 CLI 的 `--timeout` 配置 `dns.Transfer`；q root 未设置该字段，实际使用 miekg/dns 默认 2 秒。
- `--resolve-ips` 收到 `CNAME → PTR` answer 时，adapter 扫描 PTR，并按唯一 IP 查询一次；q root 强制把首条 answer 转为 PTR，可能 panic，且会重复查询相同地址。adapter 保留安全行为。
- 多 RR type/default RR type 的集合一致；adapter 固定参数顺序，q root 使用 map range，输出顺序本身不稳定。
- `--version` 标识锁定的 q 版本及 `NextTrace adapter`，不冒充官方 q release build metadata。
- 可预判的 plus flag、TLS、URL、HTTP header、DNSCrypt、AXFR 错误会返回普通 error，不复刻 q root 的 `log.Fatal`；差分测试按消息语义规范化 fatal 前缀、耗时和平台网络错误。无效 HTTP header 会在建连前失败，q root 会交给 net/http 在发送时拒绝。
- `--qid` 只接受 `-1` 或 `0..65535`；q root 会把其他整数静默截断为 `uint16`。ODoH target 会先解析 DNS Stamp 并接受解析结果为 HTTPS 的 DoH Stamp；q root 的字面 `https://` 检查会拒绝该组合。
- q v0.19.12 的 plus flag helper 会跳过 `+aa`、`+ad`、`+cd`、`+ra`、`+rd`、`+t`、`+z`；adapter 按 `cli.Flags` 的公开 long tag 正确处理这些短名称，未定义的 `+tc` 仍报错。
- adapter 按完整 question 与全部 OPT option 计算 EDNS padding，并按服务器数、RR query 数及实际 A/AAAA PTR follow-up 数配置整体 watchdog；q root 分别按空 header 计算 padding、只按服务器数计算整体 timeout。
- adapter 正确区分 bare 数值 IPv6 scope 与 RFC 6874 `%25` zone、避免把 escaped userinfo 误判为 zone，并保留 DoH scoped IPv6 URL 的单层 `%25` 编码；同时以 `0600` 创建 TLS key log、验证 AXFR 文件组件与 root containment，并修正 q root 的 scoped IPv6 debug 格式。差分测试仅对锁定版本的该条错误 debug 行做窄归一化。

## 剩余架构风险

- q transport 没有统一 context API。adapter 的整体超时覆盖查询、PTR/Whois 后处理和输出；超时后 CLI 会返回并退出，但 TLS/HTTP/QUIC/ODoH/DNSCrypt 的底层操作只能在后台继续到自身返回，QUIC 明确使用 `context.Background()`。后台期间会继续持有 DNS 独占锁及相关全局状态；后续 `Run` 可通过自身 context 取消等待，但使用 `context.Background()` 时仍会等待底层返回。
- DNSCrypt 在 Dial/证书获取失败时仍调用 `log.Fatal`，无法由 adapter 转换为 error。q output 的写入/序列化失败也会 `log.Fatal`。
- q HTTP transport 会修改 `http.DefaultTransport`。adapter 已串行化首次 Exchange、使用 clone 并恢复全局值，但安全性依赖 DNS 模式独占运行。
- 为保持 q v0.19.12 行为，plain/DoT/DoH DNS Stamp 仍按 q root 只使用 provider/path 组装 URL；stamp 的 server address/certificate hash 没有下沉到公开 transport。DNSCrypt stamp 会完整透传。
- `qutil.UseColor`、默认 charm logger、`net.DefaultResolver` 已在调用作用域内保存/恢复；JSON naming strategy 仍是 q output 的进程级全局写入，无法从公开 API 恢复。
- recursive AXFR 取消会主动关闭并 drain transfer；TLS/HTTP/QUIC/ODoH/DNSCrypt 仍无法提供严格的底层即时取消。
- recursive AXFR 会拒绝非便携 label 并做词法 containment；它假设当前目录不受恶意本地进程并发修改，不防御本地 symlink TOCTOU。
- 超时会禁止后续 stdout/stderr 写入，但若调用方提供的 writer 已在一次写入中永久阻塞，禁用操作本身也会等待；正常终端/文件路径未发现该问题。
- 2,180 行本地编排高于 q root 1,001 行，升级时存在明显的双实现漂移成本。

## 升级协议

每次更新 q 版本必须：

1. 先审查 q 的 `main.go`、`resolver.go`、`xfr.go`。
2. 审查 `cli`、`output`、`transport`、`util`、`util/tls` 的 API 和行为差异。
3. 更新 flags 快照；任何快照变化都需人工确认映射。
4. 构建对应版本官方 q，执行本地差分语料和 fatal 子进程测试。
5. 重跑三 flavor 的 `go list -deps`、`go version -m`、体积与发布矩阵。

## Phase 2 acceptance

DNSCrypt/ODoH 隔离 smoke 已完成。2026-07-27 已人工确认接受初始 1,892 行本地编排、full +3.189 MiB、上述语义差异，以及不可拦截 fatal/非统一取消风险，允许进入正式 PR review；review 修复后为 2,180 行、full +3.204 MiB。该确认不授权 Phase 3 resolver 替换。
