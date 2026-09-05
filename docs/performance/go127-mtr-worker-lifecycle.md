# Go 1.27 MTR worker 生命周期证据

## 范围与结论

本轮只统一 active trace MTR 的 worker 所有权与 shutdown 顺序：

- scheduler、preview、legacy raw round、probe、Geo/PTR metadata 和 ICMP listener 全部登记到
  session 根 context 与同一 `WaitGroup`。
- reset 只取消旧 generation，旧 probe 和 metadata 结果无法进入新 generation；旧 probe 退出前
  仍占用全局并发容量，避免连续 reset 暂时超过 `ParallelRequests`。最终 shutdown 固定执行
  “取消根 context -> 关闭 prober/listener -> 等待 worker”。
- 所有结果发送同时监听 root/generation cancellation；生产 MTR 路径不再使用循环
  `time.After` 或独立 context watcher。
- worker 使用 `pprof` 的 `owner` label；active goroutine profile 能定位 `mtr.probe`，最终
  profile 不残留任何 `mtr.*` owner。
- TUI 进程级阻塞 stdin reader 仍不纳入 session；新增注入式 reader seam 只用于验证
  pause/resume/reset/quit，终端输入语义不变。

CLI flags、输出、JSON schema、MTR 统计、协议包布局、导出 API 和三 flavor 依赖边界均不变。

## 精确版本与环境

| 项目 | 值 |
| --- | --- |
| parent | `74546d01fe4c50ae3da0dbd1215398017faf955e` |
| exact measured code head | `7be9fe5812f17d8a4dd10f40d1c21210cc26e462` |
| 主机 | Apple M5，10 核，32 GB 内存，AC 供电 |
| 系统 | macOS 26.6.2，darwin/arm64 |
| 工具链 | Go 1.27.1，`GOEXPERIMENT=nojsonv2` |
| benchmark | `GOMAXPROCS=10`，每次 1 秒；完整 harness 10 次，越线项 20 次 |
| profile | `GOMAXPROCS=10`，MTR Snapshot 30 秒；worker goroutine raw profile |
| 统计工具 | `benchstat v0.0.0-20260825160852-19be9d8e6c70` |

证据提交只加入本文档，不改变被测 Go 行为、fixture 或 benchmark harness。PR 性能工作流会在
exact head 生成 active/final goroutine profile，并另存 Linux cross-reference artifact。

## 调用链变化

### 旧路径

`RunMTR -> scheduler/loop -> detached probe/metadata/preview/listener goroutines`

不同路径各自启动 goroutine、持有 context 或等待结果。reset 依赖 generation 数值过滤，但旧
worker 没有统一取消与登记；shutdown 中存在先等待 worker、再关闭可解除阻塞的 prober/listener
的环形依赖风险。部分间隔使用 `time.After`，取消后 timer 不能主动停止。

### 新路径

`RunMTR -> mtrWorkerSession(root) -> generation -> registered workers -> cancel/close/wait`

session 是唯一 worker owner。scheduler 启动时把 prober 与 ICMP listener 注册到同一 session；
probe、同步/异步 metadata、preview 和 legacy raw round 通过 `session.Go(owner, fn)` 启动。
reset 先取消旧 generation，再清空该 generation 的 hop 状态并建立新 generation；旧结果在消费
侧丢弃业务数据，但 worker completion 仍释放跨 generation 的全局并发账本。最终退出由 session
先取消根 context、关闭资源以解除 I/O，再等待全部 worker。

ICMP listener 首次启动和 seq 回卷后的轮换都登记为 `mtr.icmp-listener`。engine 的 spec 使用
typed atomic pointer，echo ID 使用 typed atomic，关闭通过 swap-to-nil 串行化，避免 listener
轮换、发送与 shutdown 互相复制或竞态。

## 生命周期与压力验证

定向测试覆盖：

- reset 取消旧 probe generation，只有新 generation 结果计入统计；
- 取消中的旧 probe 退出前仍占用全局容量，新 generation 不会超过 `ParallelRequests`；
- shutdown 必须先关闭 prober，再等待被其解除阻塞的 worker；
- initial/rotated listener 与 preview worker 都由 session join；
- probe、Geo/PTR metadata 与 raw round 发送在 root/generation 取消后可立即退出；
- 注入式 TUI reader 的 pause、reset、resume、quit 顺序不变。

结果：

| 验证 | 结果 |
| --- | --- |
| 生命周期定向测试 | 100 次通过 |
| reset generation stress | 1,000 次通过 |
| 定向 race | 20 次通过 |
| active raw goroutine profile | `owner=mtr.probe`，1/4 goroutine |
| final raw goroutine profile | 无 `owner=mtr.*` label |

Go 不能强制终止忽略 timeout/context 的外部自定义 `ipgeo.Source` 回调；内建 provider 已遵守
context 与 timeout。本轮保持该既有外部合同，不宣称能回收违规回调内部自行创建的 goroutine。

## Benchmark

parent 与实现 head `97439fe` 先使用完整 Go 1.27.1 `nojsonv2` harness 各顺序运行 10 次。
review 修复完成后，预编译 parent 与 exact head `7be9fe5` 的 trace test binary，并按奇偶轮交换
先后顺序交替采样 20 次，避免长跑温度和执行顺序偏差。最终 exact-head 结果如下：

| Benchmark | parent | exact head | benchstat | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| MTR Update 64x4 | 47.67 us | 48.05 us | 不显著，`p=0.529` | 143,360 -> 143,360 | 834 -> 834 |
| MTR Clone 64x4 | 445.6 ns | 451.4 ns | 不显著，`p=0.387` | 3,408 -> 3,408 | 4 -> 4 |
| MTR Snapshot 64x4 | 6.478 us | 6.654 us | 不显著，`p=0.242` | 49,152 -> 49,152 | 257 -> 257 |
| MTR preview COW 64x4 | 12.16 us | 12.55 us | 不显著，`p=0.149` | 97,008 -> 97,008 | 283 -> 283 |
| geomean | 6.396 us | 6.523 us | +1.98% | 39,064 -> 39,064 | 124.8 -> 124.8 |

四项在 20 次校准后均未检出显著时间差异，分配完全不变；geomean 只记录各项中位数的几何
平均，不单独提供显著性判断。生命周期自身以取消、join、race 和 goroutine profile 验证；
现有 harness 没有执行真实网络 worker 生命周期的稳定微基准。

完整 harness 中未修改路径也出现纳秒级越线项，均补到 20 次：GeoFeed parse `+0.82%`、IPv4
prefix-map `-5.89%`、MTU decoder 包级 geomean `+0.36%`、Geo HTTP client construct 无显著
差异；相同热状态下 UDPv6 decoder 为 parent 91.20 ns、head 91.17 ns，无显著差异。Geo cache
miss 为 45.30 ns -> 46.26 ns（`+2.14%`），但 `trace/cache.go` 无 diff，`geoCacheRuntime.load`
的低位对齐不变；新增生产代码和测试改变了 benchmark caller 在测试二进制中的位置。该结果
作为布局敏感的未归因风险保留，不把它算作生命周期改善或回退。

## Profile

parent/exact head 对相同 `BenchmarkMTRAggregatorSnapshot64TTL4Paths` 各采集 30 秒 CPU 与 heap
profile：

| 指标 | parent | exact head |
| --- | ---: | ---: |
| ns/op | 6.282 us | 6.694 us |
| B/op | 49,152 | 49,152 |
| allocs/op | 257 | 257 |

两侧 CPU top 都由 Darwin runtime wait、GC 与系统调用构成，没有新增业务热点。heap alloc-space
均全部归于 `trace.cloneMTRStats`；profile 单次吞吐不用于性能门槛判断，该 benchmark 也不执行
session 生命周期，仅作全局交叉回归。

## 产物大小与测试耗时

Darwin arm64 产物使用 `-buildvcs=false -trimpath -ldflags '-s -w -buildid='`，并以相同
UPX `--force-macos -9` 压缩：

| Flavor | parent 未压缩 | exact head 未压缩 | parent UPX | exact head UPX |
| --- | ---: | ---: | ---: | ---: |
| nexttrace | 30,126,706 B | 30,143,250 B | 10,141,712 B | 10,141,712 B |
| nexttrace-tiny | 11,050,018 B | 11,066,562 B | 4,259,856 B | 4,276,240 B |
| ntr | 11,050,018 B | 11,066,562 B | 4,259,856 B | 4,276,240 B |

未压缩均增加 16,544 B；完整版 UPX 后不变，tiny/ntr UPX 后各增加 16,384 B。增长来自统一
session 与 owner label 代码，没有新增依赖。

同配置、预热缓存后的 `go test -count=1 ./...` 墙钟为 parent 24.21 秒、初始实现 head 23.87 秒；
exact measured code head 另通过完整 default/nojsonv2、race 与跨平台门禁，只记录完成成本，不解释
为性能改善。

## 平台风险与回退

主要风险是 reset 与在途结果竞争、跨 generation 全局并发账本、listener 轮换期间关闭 spec、
shutdown 的 close/wait 顺序，以及外部自定义 Source 不履行 timeout。generation 结果过滤、
worker completion 账本、typed atomic、统一 session owner、100/1,000 次压力、race 和
active/final goroutine profile 覆盖这些边界。

Darwin 最低版本保持 macOS 13.0，没有新增平台 API。Windows/Linux 仍使用原有 prober 与 listener
实现，只有外围 owner 与取消顺序变化。

如需回退，可撤销生命周期实现、合同测试、性能 workflow 和本文档。没有配置、JSON、协议、
持久数据或导出 API 迁移；回退不需要数据处理。原始 benchmark、profile、测试日志和二进制
不入库，由本地忽略目录及 CI artifact 保存。
