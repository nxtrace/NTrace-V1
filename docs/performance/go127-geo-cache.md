# Go 1.27 Geo 缓存边界与隔离证据

## 范围与结论

本轮只调整 Geo 数据源身份、进程级缓存和内建调用点：

- `ipgeo.SourceDescriptor` 明确 Source、canonical namespace/backend 和可选
  generation；旧 `GetSource`、`GetSourceSession`、`LookupIPGeo` API 保留。
- 内建 CLI、REST/WS、service/MCP、MTR、FastTrace、MTU、nali 和 speedtest 使用
  descriptor；无 namespace 的外部自定义 Source 绕过进程缓存和 singleflight。
- 全局缓存固定为 4096 项、15 分钟绝对 TTL、FIFO 淘汰；命中不续期、不改变
  FIFO 顺序，错误和 nil 结果不缓存。
- `ClearCaches` 增加 epoch 屏障。清理前的 flight 不能与清理后的请求合并，也不能
  在清理后回填旧结果。
- 缓存存储和每个调用方都获得独立 `IPGeoData` 副本，包含 `Router` map/slice
  深拷贝，避免 renderer 或调用方修改共享对象造成污染和 data race。

PR-4 没有数值性能合并门槛。旧实现只是无界 `sync.Map[string]*IPGeoData`，直接返回
共享指针；新实现承担 key 规范化、容量/TTL/FIFO/epoch 管理和返回值隔离，因此串行
命中成本明确增加。完整 lookup 的中位数仍为 137.8 ns/op，并发命中为 58.33 ns/op。

## 精确版本与环境

| 项目 | 值 |
| --- | --- |
| parent | `e1338fc54c672386877b1576af684295fbd4dba7` |
| descriptor commit | `20d027771e09c32df4ec0c2d294555c800dac8de` |
| implementation/profile head | `c865f0c436f0b5ce839c293763773f5af4b3ab24` |
| 主机 | Apple M5，10 核，32 GB 内存，AC 供电 |
| 系统 | macOS 26.6.2，darwin/arm64 |
| 工具链 | Go 1.27.1，`GOEXPERIMENT=nojsonv2` |
| benchmark | `GOMAXPROCS=10`，每组 10 次，每次 1 秒 |
| 统计工具 | `benchstat v0.0.0-20260825160852-19be9d8e6c70` |

## 调用链变化

### 旧路径

普通非 DN42 查询执行：

`Hop.fetchIPData -> sync.Map(IP text) -> global singleflight(IP text) -> Source`

缓存 key 只有原始 IP 文本，不区分 provider、NextTrace v3/v4 backend、语言或
maptrace。缓存无容量和 TTL，返回同一个可变指针。DN42 和部分 direct/service 路径
则绕过该缓存，内建入口之间没有统一身份。

### 新路径

内建入口先建立 descriptor/session，再执行：

`request/session -> Config.IPGeoDescriptor -> bounded Geo cache -> descriptor.Source`

key 包含：

- `netip.Addr.Unmap()` 后的地址；
- canonical namespace 和实际 backend；
- trim/lower 后的 language；
- maptrace；
- DN42 的规范化 hostname 与 GeoFeed generation。

cacheable Source 使用与 key 相同的 canonical 地址、language 和 DN42 hostname，避免
IPv4-mapped 文本或语言大小写由“第一个 miss”决定后续结果。原始自定义 Source 没有
namespace 时仍收到原始参数，不参与缓存或 singleflight。

NextTrace API v3 WebSocket 与 v4 HTTP 使用不同 backend key。DN42 descriptor 的 Source
闭包和 generation 来自同一个不可变 GeoFeed 快照；refresh 只发布更高 generation，
现有 MTR 会话在 reset 边界刷新。

### 取消和清理

descriptor miss 使用 `singleflight.DoChan`，每个等待者用自己的 context/deadline 等待；
短 deadline follower 可以退出而不取消其他调用方。Source 回调仍必须履行传入的 timeout
合同，Go 不能强制终止违规回调。

清理时先推进 epoch，再清空 map/FIFO。flight key 包含 epoch，store 也核验发起时 epoch，
因此旧 flight 只能把结果返回给清理前仍在等待的调用者，不能影响清理后的缓存。

## Benchmark

parent/head 共同的底层子项使用同一命令与环境：

```sh
GOTOOLCHAIN=go1.27.1 GOEXPERIMENT=nojsonv2 GOMAXPROCS=10 \
  go test -run '^$' -bench '^BenchmarkGeoCacheAccess$' \
  -benchmem -benchtime=1s -count=10 ./trace
```

| 子项 | parent | implementation head | 变化 |
| --- | ---: | ---: | ---: |
| Hit | 8.622 ns/op, 0 B, 0 alloc | 86.30 ns/op, 288 B, 1 alloc | +900.99% |
| Miss | 5.002 ns/op, 0 B, 0 alloc | 45.43 ns/op, 0 B, 0 alloc | +808.24% |

这两个 parent 子项只测无界 `sync.Map` 读取，不包含新合同需要的 typed key、epoch 检查和
返回值隔离，因此增幅不是同功能回退。新增子项记录最终完整路径：

| 子项 | time/op | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| FIFO eviction | 423.7 ns | 702–703 B | 5 |
| Parallel cache load hit | 48.27 ns | 288 B | 1 |
| CachedGeoSource lookup hit | 137.8 ns | 288 B | 1 |
| Parallel CachedGeoSource hit | 58.33 ns | 288 B | 1 |

288 B、1 alloc 是每个调用方独立 `IPGeoData` 的固定浅结构副本；只有非 nil Router 时
才额外复制 map 和内部 slice。测试同时覆盖 32 个 singleflight waiter，确认每个 waiter
获得不同指针且相互修改不可见。

## Profile

固定 10 秒 profile 覆盖 Hit、Miss、Eviction、Parallel、LookupHit 和
ParallelLookupHit。CPU profile 中 `geoCacheRuntime.load` 累积占 30.71%，typed-key
`runtime.typehash` 占 11.24%；heap alloc-space 的 95.74% 来自
`cloneGeoCacheValue`。这与 benchmark 的 1 alloc/op 一致，且分配用于调用方隔离，
不是隐藏的缓存增长。

原始 CPU/heap `.pprof` 和完整 benchmark 输出只作为本地/CI evidence 保存，不提交仓库。

## 产物大小

Darwin arm64 产物使用 `-buildvcs=false -trimpath -ldflags '-s -w -buildid='`，
`MACOSX_DEPLOYMENT_TARGET=13.0`，两侧均为 `nojsonv2` 未压缩产物：

| Flavor | parent | implementation head | 变化 |
| --- | ---: | ---: | ---: |
| nexttrace | 30,044,018 B | 30,093,618 B | +49,600 B / +0.1651% |
| nexttrace-tiny | 10,983,874 B | 11,016,978 B | +33,104 B / +0.3014% |
| ntr | 10,983,874 B | 11,016,978 B | +33,104 B / +0.3014% |

implementation head 的 Darwin arm64 产物 `LC_BUILD_VERSION` 为 `minos 13.0`。

## 验证

新增回归覆盖：

- provider alias、NextTrace v3/v4 backend、language、maptrace、DN42 hostname 与
  generation key 隔离；
- IPv6 等价文本、IPv4-mapped IPv6 与 canonical Source 输入；
- 15 分钟绝对 TTL、hit 不续期、FIFO 不提升、4096 默认容量；
- 错误/nil 不缓存、同 key 32 并发只调用一次 Source；
- 无 namespace Source 不缓存且不 singleflight；
- clear 与旧/新 flight 并发时的 epoch 屏障；
- 每个 hit/waiter 的 scalar、Router map 和 Router slice 深隔离；
- follower 自有 deadline、direct/descriptor caller cancellation 和 MTR metadata 有界收尾；
- CLI、server、service/MCP、FastTrace、MTU、nali、speedtest 的 descriptor 传播，
  以及 non-wide MTR report 同时清除 Source/descriptor/refresh。

implementation head 的定向普通/race 测试、20 次并发压力、全仓 `nojsonv2` 测试、
相关 vet 和 Web 前端 15 项 Node 测试均通过。全仓 `nojsonv2` 测试墙钟为 parent
32.57 秒、implementation head 18.51 秒；两次构建缓存状态不同，只作为完成耗时记录，
不作性能改善结论。紧随其后的证据提交只修改本 Markdown 文件，不改变 Go 源码或
构建输入；PR exact-head CI 仍需通过默认 JSON/nojsonv2、全仓 race、build、vet、lint、
三 flavor 和跨平台矩阵后才允许合并。

## 平台风险与回退

缓存最多保留 4096 个深拷贝结果；Router 数据较大时，内存上限还取决于单项大小。
绝对 TTL 不因命中续期。第一个同 key flight 的 Source timeout 仍是兼容兜底，等待者
自己的 context 决定其总等待预算。

新增状态只在进程内，不涉及配置、JSON、协议或持久数据迁移。如需回退，可逆序撤销
缓存实现和 descriptor 提交；旧导出 API 未删除或改签名，调用方无需迁移数据。
