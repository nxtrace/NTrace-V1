# Go 1.27 解析器 fuzz 证据

## 范围与结论

本轮为已有解析逻辑增加 11 个原生 Go fuzz 目标，覆盖终端输入、ICMP/TCP/UDP、
MPLS、DN42 GeoFeed、nali、DNS endpoint、deploy WebSocket init JSON 和 NextTrace
API v3 WebSocket 响应。

生产代码只提取两个纯解析 seam：deploy WebSocket init 继续调用同一个
`encoding/json.Unmarshal`；v3 响应继续调用同一个 gjson 字段映射函数。没有 fuzz
目标访问 raw socket、真实网络或全局连接池。

CLI flags、退出码、stdout/stderr、JSON schema、MTR 统计、TTY/ANSI、协议布局、导出
API 和三 flavor 依赖边界均不变。

## 精确版本与环境

| 项目 | 值 |
| --- | --- |
| parent | `70ddd4040a990bb83ff0005727bfe290d59cbc5e` |
| exact measured code head | `f19276ae33ee9a943ba9107ed0d701739f9b8c5d` |
| 主机 | Apple M5，10 核，32 GB，AC 供电 |
| 系统 | macOS 26.6.2，darwin/arm64 |
| 工具链 | Go 1.27.1，`GOEXPERIMENT=nojsonv2` |
| benchmark | `GOMAXPROCS=10`，每项 1 秒；完整 harness 10 次，越线项交替 20 次 |
| profile | `GOMAXPROCS=10`，`BenchmarkFindIPSpans` 30 秒 |
| 统计工具 | `benchstat v0.0.0-20260825160852-19be9d8e6c70` |

证据提交只加入本文档，不改变被测 Go 行为或 workflow。原始 benchmark、profile、
二进制和 fuzz cache 位于本地忽略目录；CI 失败时只上传最小 crash corpus。

## 解析入口

| 目标 | 输入上限 | 主要不变量 |
| --- | ---: | --- |
| `FuzzMTRInputParser` | 4 KiB | ANSI/CSI/SS3/OSC 状态和 action 范围 |
| `FuzzParseSocketICMPMessage` | 4 KiB | 明确失败、响应类型范围、marshal round-trip |
| `FuzzExtractEmbeddedICMPSeq` | 4 KiB | echo ID 匹配、sequence 范围、IPv4/IPv6 round-trip |
| `FuzzDecodeTCPProbePacket` | 4 KiB | port/seq/ack 范围、peer IP family |
| `FuzzParseEmbeddedUDPPacket` | 4 KiB | port/IP family、IPv4/IPv6 round-trip |
| `FuzzExtractMPLS` | 4 KiB | label 数量、格式、Lbl/TC/S/TTL 范围 |
| `FuzzParseGeoFeedRecord` | 64 KiB | 记录宽度、masked prefix、索引查询、CSV round-trip |
| `FuzzFindIPSpans` | 16 KiB | span 有序不重叠、边界、源文本和 IP family |
| `FuzzParseServer` | 4 KiB | endpoint 完整性、port 有效性、确定性 |
| `FuzzDecodeWSInitRequest` | 64 KiB | JSON 明确失败、请求结构 round-trip |
| `FuzzDecodeNextTraceAPIV3Message` | 64 KiB | JSON 明确失败、字段映射确定性 |

每个 callback 先按协议上限截断输入；有效输入检查字段、索引和数值范围，无效输入必须
显式返回失败。具备编码路径的格式执行 round-trip。

## 调用链变化

deploy WebSocket init 从：

`ReadMessage -> inline json.Unmarshal -> prepareTrace`

变为：

`ReadMessage -> decodeWSInitRequest -> json.Unmarshal -> prepareTrace`

NextTrace API v3 从：

`dispatch -> gjson.Parse -> field mapping`

变为：

`dispatch -> gjson.Parse -> shared field mapping`

fuzz 专用严格入口先用 `gjson.Valid` 拒绝畸形 JSON，再进入相同字段映射。生产 dispatch
仍保留原有宽松解析行为，避免改变错误语义。

## Fuzz 与 CI

本地先运行所有 seed corpus，再对 11 个目标分别执行 2–3 秒短时 fuzz；全部通过，未生成
crash corpus。该短跑只验证目标可执行和基本不变量，不替代 nightly。

`.github/workflows/fuzz.yml` 只由每日 schedule 或手动触发，不在 PR 中执行随机 fuzz。
nightly 使用 Go 1.27.1，把每个 package/target 作为独立 matrix job，单目标 fuzz 30 秒、
minimize 10 秒、`parallel=1`。普通 PR 的既有 Test workflow 会把 fuzz seed corpus 当作普通
测试执行。失败 job 只上传对应 `testdata/fuzz/<target>`，保留 14 天；不上传 Go fuzz cache。

## Benchmark

parent/head 的完整 Go 1.27.1 `nojsonv2` harness 各顺序运行 10 次。`util` 的 HTTP
benchmark 因本地端口受沙箱限制，随后在允许 loopback 的相同主机上独立补齐 10 次。
首轮超过 1% 的候选使用预编译 parent/head test binary，按奇偶轮交换先后顺序交替采样
20 次。

本 PR 直接相关且首轮未越线的结果：

| Benchmark | parent | head | benchstat | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| WS JSON marshal | 493.4 ns | 492.2 ns | 不显著，`p=0.393` | 416 -> 416 | 2 -> 2 |
| WS JSON unmarshal | 2.508 us | 2.471 us | 不显著，`p=0.190` | 656 -> 656 | 15 -> 15 |
| nali spans | 4.591 us | 4.461 us | 不显著，`p=0.190` | 6,400 -> 6,400 | 61 -> 61 |

20 轮校准结果：

| 组 | parent geomean | head geomean | 结论 |
| --- | ---: | ---: | --- |
| Geo cache + MTR Snapshot/preview | 297.2 ns | 297.2 ns | `+0.01%`，8 项均不显著 |
| ICMP/UDP decoder | 86.25 ns | 85.89 ns | `-0.42%`，4 项均不显著 |
| Geo HTTP multi-client | 46.29 us | 46.12 us | `-0.37%`，4 项均不显著 |

decoder 校准中 IPv4/IPv6 ICMP 和 UDP 的 `p` 值为 `0.733..0.836`；trace 组为
`0.090..0.963`；HTTP 组为 `0.512..0.779`。全部 B/op/allocs/op 保持一致。
首轮的 cache/MTR、ICMPv4/UDPv4 和 HTTP 并发回退未在交替采样中复现，不构成合并阻断。

## Profile

parent/head 对 `BenchmarkFindIPSpans` 各采集 30 秒 CPU 与 heap profile。两侧 CPU top
均由 `FindIPSpans`、`parseCandidate`、`strings.IndexAny` 和 `net/netip` 解析构成；heap
alloc-space 均由 `FindIPSpans`、IPv4/IPv6 parse 和错误构造主导，没有新增业务热点。

profile 单次结果为 4.524 us 与 4.778 us，B/op 都是 6,400，allocs/op 都是 61；单次
profile 吞吐只用于热点核验，不代替 10/20 次 benchstat。

## 产物大小

Darwin arm64 使用 `-buildvcs=false -trimpath -ldflags '-s -w -buildid= -macos=13.0'`
构建，并以相同 UPX 5.2.1 `--force-macos -9` 压缩：

| Flavor | parent 未压缩 | head 未压缩 | parent UPX | head UPX |
| --- | ---: | ---: | ---: | ---: |
| nexttrace | 30,143,154 B | 30,143,154 B | 10,141,712 B | 10,158,096 B |
| nexttrace-tiny | 11,066,466 B | 11,066,466 B | 4,276,240 B | 4,276,240 B |
| ntr | 11,066,466 B | 11,066,466 B | 4,276,240 B | 4,276,240 B |

未压缩大小全部不变；tiny/ntr 的 UPX 大小不变，full 的 UPX 大小增加 16,384 B。
六个 parent/head Darwin arm64 产物的 `LC_BUILD_VERSION` 均为 `minos 13.0`。

## 门禁

| 验证 | 结果 |
| --- | --- |
| `go test -count=1 ./...` | 通过，约 16.6 秒 |
| `GOEXPERIMENT=nojsonv2 go test -count=1 ./...` | 通过，约 19.2 秒 |
| `go test -race -count=1 ./...` | 通过，约 21.9 秒 |
| `go build ./...` / `go vet ./...` | 通过 |
| tiny/ntr 测试与构建 | 通过 |
| Web 前端 Node 测试 | 15/15 通过 |
| `go mod verify` / `go mod tidy -diff` | 通过，无 diff |
| actionlint | 通过 |
| golangci-lint CI 等价增量检查 | `0 issues` |
| full/tiny/ntr 跨平台脚本 | 60 个产物，脚本退出 0 |
| Darwin amd64/arm64 `LC_BUILD_VERSION` | 6/6 为 `minos 13.0` |

仓库的完整 `golangci-lint run` 仍报告 75 个既有 baseline issue；CI 配置使用
`only-new-issues: true`，本 PR 对应的 `--new-from-rev=main` 为 `0 issues`。未在本 PR
清理无关历史问题。

## 风险与回退

主要风险是 fuzz invariant 过严造成误报、nightly 成本，以及纯 seam 意外改变解析错误
语义。短时 fuzz、两套 JSON 测试、race、字段 round-trip 和保持生产 v3 宽松入口覆盖这些
边界。nightly 不执行网络或 raw socket，不会向外部系统发送请求。

如需回退，可撤销两个纯解析 seam、fuzz 文件、nightly workflow 和本文档。没有配置、协议、
JSON、持久数据或导出 API 迁移；回退不需要数据处理。
