# Go 1.27 Geo HTTP Transport 复用证据

## 范围与结论

本轮只调整 Geo HTTP 连接复用、DNS 策略快照、NextTrace API v4 Transport
生命周期和 IPDB.One token 刷新：

- 普通 provider 按不可变 `{DoT resolver, fallback}` 策略共享 Transport；默认策略
  使用 `sync.OnceValue`，非默认策略使用最多 32 项的 FIFO 池。
- NextTrace API v4 使用独立的策略 Transport 池；timeout 和 token 不进入 key，也不再
  修改普通 provider 的共享实例。
- IPDB.One 的首次及过期 token 刷新使用 singleflight 合并；每个查询仍受调用者的
  原始总预算约束。

既有 `NewGeoHTTPClient` 保持签名及独立、可配置 Transport 语义；新增的
`NewGeoHTTPClientWithPolicy` 也返回独立 Transport，内建 provider 则显式改用新增的
共享接口。CLI、REST/WS、MCP、JSON、显式错误语义和三 flavor 边界不变；不把底层
context/http 超时包装文本作为稳定合同。

相对 parent，生产路径的 client 构造从 7 次分配降为 1 次；在最终 exact head 内，
共享构造器相对兼容独立构造器从 6 次降为 1 次，构造耗时下降 90.25%。四 client
并发请求未检出显著耗时差异，同时少一次分配。连接计数测试确认 100 次顺序请求
最多建立 3 个连接，100 轮、每轮 4 个并发请求最多建立 8 个连接。

## 精确版本与环境

| 项目 | 值 |
| --- | --- |
| parent | `284282979f88f81a62a8d987189b8711174d02d5` |
| full-suite benchmark head | `407d84394397f0aa21ed7b05ab611afdb2e3ba75` |
| shared-path profile head | `407d84394397f0aa21ed7b05ab611afdb2e3ba75` |
| final focused head | `dfd0fb645eb30c102662fb66a36609568c26a77e` |
| 主机 | Apple M5，10 核，32 GB 内存，AC 供电 |
| 系统 | macOS 26.6.2，darwin/arm64 |
| 工具链 | Go 1.27.1，`GOEXPERIMENT=nojsonv2` |
| benchmark | `GOMAXPROCS=10`，每组 10 次，每次 1 秒 |
| 统计工具 | `benchstat v0.0.0-20260825160852-19be9d8e6c70` |
| 压缩工具 | UPX 5.2.1，`-9` |

`dfd0fb6` 恢复既有 `NewGeoHTTPClient` 的动态 DNS 与 Dialer timeout 语义，并
增加回归测试；它把 DefaultTransport clone 逻辑等价抽成 helper，但未改变共享
策略、连接池或 benchmark 语义。

## 调用链变化

### 普通 provider

此前每次查询执行：

`provider -> NewGeoHTTPClient -> DefaultTransport.Clone -> 独立连接池`

现在内建 provider 执行：

`provider -> NewSharedGeoHTTPClient -> policy pool -> 共享不可变 Transport`

Transport 仍从 `http.DefaultTransport` 克隆，保留 proxy、TLS、HTTP/2 和标准连接池
行为。Dialer 不固化业务 timeout，使用 request context 作为总预算；DNS 返回的 IP
按原顺序尝试，TLS SNI 仍为 URL host。默认 Transport 的隐式每 host 空闲连接上限
扩为 32，避免四个短生命周期 client 并发时反复关闭连接；显式自定义值不改写。

默认策略只构造一次。非默认策略的 FIFO 命中不移动顺序，超过 32 项时淘汰最早
插入项，并在锁外关闭其空闲连接。

### NextTrace API v4

NextTrace API v4 现在按 endpoint、不可变 DNS policy 和完整 proxy policy 复用独立
Transport。token 与 timeout 不进入 key；每次调用只创建轻量 client，timeout 由
request context 控制，`http.Client.Timeout` 只作兼容兜底。

环境代理快照包含 `HTTP_PROXY`、`HTTPS_PROXY`、`NO_PROXY` 及 CGI 状态；代理函数
仍对每次请求和重定向 URL 重新求值。显式 `NEXTTRACE_PROXY` 固定使用指定代理。
FastIP 仅用于初始 endpoint 的直连场景；失败时回到该请求捕获的 DNS policy
Dialer，不读取后来变化的全局 resolver。TLS SNI 保持 endpoint host。

### Geo DNS scope

`GeoDNSPolicy` 是规范化、可比较的值快照。空 resolver scope 与非空 scope 使用同一
串行化和恢复路径；相同 resolver 允许安全嵌套，不同并发 scope 不再互相污染。

### IPDB.One token

首次与过期 token 刷新使用共享 singleflight。32 个同预算并发调用只进行一次认证；
错误不缓存，token 有效期仍为 30 秒。flight 继承发起者的绝对 deadline，但不因其
手动 cancel 中断其他 waiter；较长预算 waiter 若加入一个较短 deadline 的 flight，
可在短 flight 超时后于自身剩余预算内重新竞争。认证与随后查询始终共享原始总预算。

## Benchmark

生产 provider 已从兼容构造器切换到共享构造器。下表在同一个 exact head、同一轮
运行中，把共享 benchmark 重命名为兼容路径后交给 benchstat 比较：

| Benchmark | 独立 Transport | 共享 Transport | 变化 |
| --- | ---: | ---: | ---: |
| client construct | 174.00 ns | 16.96 ns | -90.25% |
| multi-client sequential | 29.42 us | 29.46 us | `~` |
| multi-client concurrent | 72.16 us | 71.60 us | `~` |
| construct B/op | 1,232 B | 48 B | -96.10% |
| construct allocs/op | 6 | 1 | -83.33% |
| concurrent B/op | 24.35 KiB | 24.37 KiB | +0.12% |
| concurrent allocs/op | 293 | 292 | -0.34% |

`~` 表示 benchstat 未确认显著差异。顺序和并发请求均未检出显著差异；并发路径
约 0.12% 的 B/op 增量同时伴随一次分配减少。

parent 与 head 的全套 benchmark 按顺序各运行 10 次。未修改的 GeoFeed、nali、
WebSocket、协议 decoder 和 MTU decoder 同时出现方向不一致的 3% 到 13% 波动，
而分配数全部不变，因此这些未修改路径不作 PR-2 归因。最终 `dfd0fb6` focused
复测还直接比较既有独立构造器：parent 到 head 的 construct 为 228.8 ns ->
174.0 ns（-23.93%）、1,680 B -> 1,232 B（-26.67%）、7 -> 6 allocs；
multi-client sequential 为 29.55 us -> 29.42 us，concurrent 为 71.52 us ->
72.16 us，两项均无显著差异。既有 API 的请求性能未检出显著回退，构造开销降低。

## Profile

`MultiClientConcurrent` 分别以 `-benchtime=30s` 采集 CPU 与 heap profile：

| 指标 | parent 独立 Transport | head 共享 Transport |
| --- | ---: | ---: |
| benchmark | 75.991 us | 74.517 us |
| 分配 | 24,899 B/op | 24,926 B/op |
| 分配次数 | 293 allocs/op | 292 allocs/op |

CPU profile 两侧结构一致：`syscall.rawsyscalln` 分别占 42.09% 与 42.51%，
`pthread_cond_wait` 15.34% 与 15.43%，`kevent` 13.75% 与 13.31%。heap profile
中 `readMIMEHeader` 分别占 16.30% 与 16.40%，`NewRequestWithContext` 占
5.66% 与 5.75%，Transport `getConn` 占 5.68% 与 5.31%。两侧累计 alloc space
不直接比较；每次迭代分配和热点比例未出现结构性回退。

## 产物大小

产物使用 `-buildvcs=false -trimpath -ldflags '-s -w -buildid='`；Darwin 另加
`-macos=13.0`。本轮不改变 flavor 依赖边界。

### Darwin arm64，未压缩

| Flavor | parent | head | 变化 |
| --- | ---: | ---: | ---: |
| nexttrace | 30,010,818 B | 30,010,850 B | +32 B / +0.000107% |
| nexttrace-tiny | 10,934,146 B | 10,934,162 B | +16 B / +0.000146% |
| ntr | 10,934,146 B | 10,934,162 B | +16 B / +0.000146% |

### Linux arm64，未压缩 / UPX `-9`

| Flavor | parent | head | 未压缩变化 | UPX 变化 |
| --- | ---: | ---: | ---: | ---: |
| nexttrace | 29,622,396 / 9,686,712 B | 29,687,932 / 9,693,332 B | +0.221% | +0.068% |
| nexttrace-tiny | 10,879,100 / 4,068,500 B | 10,879,100 / 4,074,040 B | 0.000% | +0.136% |
| ntr | 10,879,100 / 4,068,396 B | 10,879,100 / 4,073,952 B | 0.000% | +0.137% |

Linux full 增加约 64 KiB，tiny/ntr 未压缩产物未观察到体积增加；现有数据不对
链接器裁剪和代码布局作单一因果归因。三种 flavor 的现有依赖边界未扩大。压缩大小
会受符号和代码布局影响，不单独作为运行时回退判据。

## 验证

除完整包测试外，新增回归覆盖：

- 100 次顺序请求，以及 100 轮、每轮 4 个并发请求的连接复用上限。
- 坏/好地址 fallback 顺序、TLS SNI、HTTP proxy 子进程和真实 HTTPS CONNECT。
- 重定向逐 URL 代理判定、`NO_PROXY`、完整代理配置 identity 和显式代理。
- dial、response header、body read 的 request cancellation。
- 32 项 FIFO、命中不刷新顺序、淘汰后关闭空闲连接。
- 空 resolver scope、相同策略嵌套、不同并发 scope 以及 race。
- NextTrace API v4 并发 Transport cache 和 FastIP fallback。
- IPDB.One 首次/过期 32 并发 singleflight、错误重试、TTL 和长短预算竞争。

head 通过默认 JSON 与 `nojsonv2` 完整测试、race、build、vet、full/tiny/ntr、
Web 前端 Node 测试、module verify/tidy diff，以及 Linux、Windows、Darwin 现有
构建矩阵。Darwin release-style 三 flavor 的 `LC_BUILD_VERSION` 继续为
`minos 13.0`。

相同 `nojsonv2` 完整测试的墙钟耗时为 parent 19.67 秒、head 25.63 秒；head 的
默认 JSON 完整测试为 19.53 秒，race 为 23.35 秒。单次测试耗时只用于保存 exact
head 门禁成本，不作性能结论。

## 平台风险与回退

共享 Transport 会延长空闲连接和 DNS 策略对象的生命周期。普通非默认策略池与
NextTrace API v4 策略池各有 32 项硬上限，默认策略另由 `OnceValue` 持有；淘汰会
主动关闭空闲连接。request context 仍是总预算；预算未耗尽且所有地址均失败时返回
最后一个连接错误，预算耗尽时返回 context 错误。代理、HTTP/2、TLS 和系统证书
行为继承标准 Transport。

如需回退，可按逆序撤销五个实现提交；旧导出 API 未删除或改签名，无需迁移配置、
缓存、JSON 或持久数据。原始 benchmark、profile 和二进制留作 CI/local artifact，
不提交仓库。
