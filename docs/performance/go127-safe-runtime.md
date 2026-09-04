# Go 1.27 安全运行时现代化证据

## 范围与结论

本轮只迁移已能证明语义等价的运行时接口：

- MTR/TUI 并发状态从函数式 atomic API 迁移到 typed atomic，并显式初始化
  `-1` sentinel。
- speed test 的普通传输 worker 使用 `WaitGroup.Go`。
- 已覆盖测试的集合、排序、查找和地址拼接改用 `slices`、`cmp`、
  `sync.Map.Clear` 和 `net.JoinHostPort`。
- packet size 与 MTR echo ID 的非安全随机改用 `math/rand/v2`。

CLI、JSON、TTY、协议报文、导出 API 和三 flavor 边界不变。平衡复测未发现
显著性能回退，分配指标不变，满足 PR-1 的合并门槛。

## 精确版本与环境

| 项目 | 值 |
| --- | --- |
| parent | `5e58ef2b0bdc3c5668a8378abf37716c5b5bb56c` |
| benchmark head | `fcd1336c43f36de61c3fa05fbccf3b04880f9f1b` |
| sentinel review follow-up | `8d36dc74060089e575ab1c1741494de249717169` |
| 主机 | Apple M5，10 核，32 GB 内存，AC 供电 |
| 系统 | macOS 26.6.2，darwin/arm64 |
| 工具链 | Go 1.27.1，`GOEXPERIMENT=nojsonv2` |
| benchmark | `GOMAXPROCS=10`，每次 1 秒 |
| 统计工具 | `benchstat v0.0.0-20260825160852-19be9d8e6c70` |
| 压缩工具 | UPX 5.2.1，`-9` |

benchmark head 之后只统一了生产与测试的 sentinel 构造 helper 并增加本报告，
没有修改被测热点；性能工作流会在 PR exact head 上重新生成 Linux
cross-reference artifact。

## 调用链变化

### MTR/TUI 状态

`atomic.Load/Store/Add/Swap/CompareAndSwap*` 改为字段自身的 typed atomic 方法。
`knownFinalTTL` 与 `roundFinalTTL` 仍以 `-1` 表示未知，并在构造函数中显式
`Store(-1)`。相关结构始终通过指针使用，`go vet -copylocks` 未发现复制已使用
atomic 的路径。

### 普通 worker

speed test transfer 的 `Add(1) -> go -> defer Done()` 改为 `WaitGroup.Go`。
协议收发、WebSocket 和 MTR 生命周期没有迁移；这些路径分别留给 PR-6A、
PR-6B 和 PR-6C。

### 标准库集合接口

- speed test 延迟样本使用 `slices.Sort`。
- candidate 使用 `slices.SortStableFunc` 与 `cmp.Compare`，继续保持健康状态优先、
  RTT 升序和相同 RTT 的输入顺序。
- `StringInSlice` 使用 `slices.Contains`。
- Geo cache 清理使用 `sync.Map.Clear`。
- WebSocket 地址使用 `net.JoinHostPort`，覆盖 IPv4、IPv6、已加括号 IPv6、zone
  和空 host。

### 非安全随机

packet size 使用 `rand/v2.IntN`，MTR echo ID 使用 `rand/v2.IntN` 并继续保留
进程 ID 低 8 位。范围测试各执行 1000 次。raw socket 结构、TCP/UDP/ICMP
报文和 QUIC payload 均未修改。

## `go fix` 审计

每个 analyzer 在 parent 临时工作树中独立运行并逐项核对 diff：

- 接受：MTR/TUI 的 `atomictypes` 子集、transfer worker 的 `waitgroupgo` 子集。
- 手工采用：有明确测试的 `slices`、`cmp`、`Map.Clear`、`JoinHostPort` 和
  `rand/v2` 子集。
- 拒绝：协议收发、wshandle 和 renderer 的 `waitgroupgo`；全仓 `any`；会改变
  JSON 省略规则的 `omitzero`；无调用者 legacy server aggregator 的
  `mapsloop`；其余跨主题或格式噪声建议。

## Benchmark

第一轮按 parent -> head 各运行 10 次；系统负载变化使未修改的 decoder 同时
出现约 5% 到 14% 的回退、MTU decoder 同时出现约 7% 到 8% 的改善。随后按
head -> parent 反向各补 10 次。合并后的关键结果如下：

| Benchmark | parent | head | 变化 |
| --- | ---: | ---: | ---: |
| MTR Update 64x4 | 92.97 us | 95.23 us | `~` |
| MTR Clone 64x4 | 43.37 us | 42.75 us | `~` |
| MTR Snapshot 64x4 | 31.41 us | 32.12 us | `~` |
| MTR preview clone/update 64x4 | 80.40 us | 86.35 us | `~` |
| Geo cache hit | 7.373 ns | 7.273 ns | `~` |
| Geo cache miss | 4.887 ns | 4.593 ns | -6.03% |
| WebSocket JSON marshal | 555.1 ns | 540.9 ns | -2.55% |
| WebSocket JSON unmarshal | 2.664 us | 2.646 us | `~` |
| Geo HTTP multi-client concurrent | 81.37 us | 83.73 us | `~` |
| nali span scan | 4.789 us | 4.843 us | `~` |

`~` 表示 benchstat 未确认显著差异。所有 allocs/op 均与 parent 相同。

合并结果仍把未修改的 GeoFeed IPv6 miss 判为 `+5.42%`，并把四个未修改的
协议 decoder 判为 `+2.35%` 到 `+5.30%`。因此对这些异常项在同一个工作树、
同一路径中切换精确 SHA，按 AB/BA 各半交替运行 10 次：

| 复测项 | parent | head | 变化 |
| --- | ---: | ---: | ---: |
| GeoFeed IPv6 miss | 13.87 us | 14.00 us | `~` |
| ICMPv4 decoder | 87.06 ns | 87.34 ns | `~` |
| ICMPv6 decoder | 90.95 ns | 90.59 ns | `~` |
| TCPv4 decoder | 16.57 ns | 16.55 ns | `~` |
| TCPv6 decoder | 16.35 ns | 16.44 ns | `~` |
| UDPv4 decoder | 82.65 ns | 82.95 ns | `~` |
| UDPv6 decoder | 84.33 ns | 84.19 ns | `~` |

同路径 decoder 几何均值变化为 `+0.09%`，无显著差异；全套结果中的异常来自
运行顺序、系统负载和不同工作树测试二进制布局，不能归因于 PR-1。

## Profile

`BenchmarkMTRAggregatorSnapshot64TTL4Paths` 分别采集 30 秒 CPU 与 heap
profile：

| 指标 | parent | head |
| --- | ---: | ---: |
| benchmark | 27.562 us | 27.641 us |
| 分配 | 106,544 B/op | 106,544 B/op |
| 分配次数 | 458 allocs/op | 458 allocs/op |
| `snapshotLocked` CPU cumulative | 26.97% | 27.88% |
| `snapshotLocked` alloc space | 90.38% | 90.43% |
| `buildMTRHopStat` alloc space | 7.67% | 7.62% |

热点结构未改变；`snapshotLocked` 与 `buildMTRHopStat` 仍是 PR-5 的优化目标。

## 产物大小

构建参数为 `-buildvcs=false -trimpath -ldflags '-s -w -buildid='`。

### Darwin arm64，未压缩

| Flavor | parent | head | 变化 |
| --- | ---: | ---: | ---: |
| nexttrace | 29,994,386 B | 30,010,914 B | +0.055% |
| nexttrace-tiny | 10,901,186 B | 10,934,226 B | +0.303% |
| ntr | 10,901,186 B | 10,934,226 B | +0.303% |

### Linux arm64，未压缩 / UPX `-9`

| Flavor | parent | head | 未压缩变化 | UPX 变化 |
| --- | ---: | ---: | ---: | ---: |
| nexttrace | 29,622,396 / 9,682,520 B | 29,622,396 / 9,686,344 B | 0.000% | +0.039% |
| nexttrace-tiny | 10,813,564 / 4,063,688 B | 10,879,100 / 4,068,364 B | +0.606% | +0.115% |
| ntr | 10,813,564 / 4,063,672 B | 10,879,100 / 4,068,476 B | +0.606% | +0.118% |

tiny/ntr 的大小增长与本轮新增 `rand/v2` 依赖同时出现；现有测量没有把依赖、
符号布局等因素分离，因此不作单一因果归因。full 的 Linux 未压缩产物不变，
没有跨 flavor 引入 WebUI/MCP 依赖。

## 验证

parent 与 head 在 `nojsonv2` 下的 `go test -count=1 ./...` 分别为 36.08 秒和
35.74 秒。
head 还通过：

- 默认 JSON 与 `nojsonv2` 的完整测试。
- `go test -race -count=1 ./...`。
- `go build ./...`、`go vet ./...`、`go vet -copylocks ./cmd ./trace`。
- full、tiny、ntr 的 tagged 测试和构建。
- Linux amd64、Windows amd64、Darwin arm64 构建。
- Web 前端 15 项 Node 测试。
- `go mod verify`、空的 `go mod tidy -diff`。
- `golangci-lint v2.13.2 --new-from-rev origin/main`，0 个新增问题。
- Darwin release-style 产物的 `LC_BUILD_VERSION minos 13.0`。

## 风险与回退

`math/rand/v2` 会改变非安全随机序列，但 packet size 范围和 echo ID 位布局保持
不变，随机序列本身不是公共合同。typed atomic 不能复制；当前目标结构只通过
指针使用，并由 copylocks 检查约束。

如需回退，可按逆序撤销三个实现提交；无需迁移配置、缓存、JSON 或持久数据。
本地原始 benchmark、profile 和二进制不入库，PR 性能工作流会保存 Linux
cross-reference artifact。
