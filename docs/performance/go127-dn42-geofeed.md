# Go 1.27 DN42 GeoFeed 索引证据

## 范围与结论

本轮只调整 DN42 GeoFeed 的装载、最长前缀查询和执行边界：

- IPv4/IPv6 分别按实际出现的 prefix bits 建立不可变 prefix map，完整构造后以
  `atomic.Pointer` 发布。
- CLI、REST/WS、MCP/service、FastTrace、nali、MTU 和 MTR 在会话开始时固定
  GeoFeed generation；MTR reset 才刷新到新 generation。
- 文件变化只在执行边界按 path、mtime、size 检查，不增加常驻 watcher；热
  `GeoFeedIndex.Lookup` 不访问文件系统。
- DN42 查询绕过不适用的保留地址过滤、进程级 Geo cache 和 singleflight。

混合 4096 条 IPv4/IPv6、8 种 prefix length 的最终数据见下文。prefix map 的热
查询保持 0 alloc/op，并超过相对预解析旧 slice 至少 20 倍的合并门槛。测试用 trie
没有在 IPv4/IPv6 两组都形成优势；prefix map 更简单，且直接表达实际出现 prefix
bits 的合同，因此选用 prefix map。

## 精确版本与环境

| 项目 | 值 |
| --- | --- |
| parent | `d2e27a66fbc13a4056d7cc4bf1d6c6da30164511` |
| production benchmark head | `9ee2d1c53d6022a0d9990a38d184d9a38c371251` |
| final code head | `c844e49e09e29cec3e9789ac2c223e92adcb08bc` |
| 主机 | Apple M5，10 核，32 GB 内存，AC 供电 |
| 系统 | macOS 26.6.2，darwin/arm64 |
| 工具链 | Go 1.27.1，`GOEXPERIMENT=nojsonv2` |
| benchmark | `GOMAXPROCS=10`，每组 10 次，每次 1 秒 |
| 统计工具 | `benchstat v0.0.0-20260825160852-19be9d8e6c70` |
| 压缩工具 | UPX 5.2.1，`-9` |

## 调用链变化

### 旧生产查询

此前每次 DN42 Geo 查询执行：

`DN42 -> GetGeoFeed -> ReadGeoFeed -> os.Open -> csv.ReadAll -> ParseCIDR -> sort -> linear scan`

文件读取、完整 CSV 解析、CIDR 构造和排序都位于逐 IP 热路径。MTR、Web 和批量
nali 查询会重复这些工作。

### 新生产查询

会话边界现在执行：

`GetSourceSession -> LoadGeoFeedIndex -> stat/reload if changed -> streaming CSV -> build index -> atomic publish`

同一会话的每次热查询只执行：

`session Source -> netip.Addr.Unmap -> descending present bits -> prefix map lookup`

IPv4 与 IPv6 使用独立索引。相同 prefix 的最后一条有效记录覆盖之前记录；显示用
CIDR 和字段仍保留输入值。IPv4-mapped IPv6 在索引内归一化为 IPv4，以便等价地址
命中相同记录，旧 `GeoFeedRow.IPNet` 适配仍按原 CIDR 重建。

### Reload 与会话 generation

首次访问惰性装载。后续边界按 path、mtime、size 识别变化；完整解析成功后才增加
generation 并发布。CSV 短行、5 列和坏 CIDR 作为记录错误跳过；CSV 结构或 I/O
错误使 reload 失败并保留旧快照。空文件是有效新快照。

普通 traceroute、FastTrace、nali、MTU、REST/WS 和 service/MCP 在请求或批次开始时
固定 source。MTR legacy 与 per-hop 两条 reset 路径先隔离旧工作，再刷新 source，
因此旧 generation 的 metadata 结果不会写入 reset 后统计。

## Benchmark

比较包含：

- 旧生产端到端读取、解析、排序、线性查询。
- 预解析旧 slice 的纯线性查询。
- 最终 prefix map。
- 仅用于选择的数据结构 trie。

| Family / implementation | time/op | B/op | allocs/op | prefix map 相对预解析旧 slice |
| --- | ---: | ---: | ---: | ---: |
| IPv4 / legacy end-to-end | 994.3 us | 1.593 MiB | 24.61k | — |
| IPv4 / legacy preparsed slice | 15.31 us | 0 B | 0 | — |
| IPv4 / prefix map | 74.50 ns | 0 B | 0 | 205.5x |
| IPv4 / test-only trie | 47.59 ns | 0 B | 0 | — |
| IPv6 / legacy end-to-end | 1.343 ms | 1.686 MiB | 24.61k | — |
| IPv6 / legacy preparsed slice | 11.56 us | 0 B | 0 | — |
| IPv6 / prefix map | 75.34 ns | 0 B | 0 | 153.4x |
| IPv6 / test-only trie | 150.7 ns | 0 B | 0 | — |

PR-0 同名兼容 benchmark 也在 parent/head 各运行 10 次。`ReadGeoFeedCSV` 从
1,179.5 us 降为 647.5 us（-45.11%），B/op 从 2.991 MiB 降为 1.028 MiB
（-65.62%）；完整 legacy view 构造的 allocs/op 从 24.63k 增为 28.68k
（+16.47%），但该构造只在装载/兼容接口边界执行，不在固定会话的查询热路径。

首轮还发现 `FindGeoFeedRow` 命中路径因无必要防御性复制增加 3 alloc/op；最终实现
恢复该旧接口原有的浅返回语义，所有命中/未命中子项重新保持 0 alloc/op，geomean
从 3.310 us 降为 3.059 us（-7.59%）。七个子项改善 4.48% 到 13.72%；IPv4
HeadHit 从 18.98 ns 变为 19.33 ns（+1.84%，绝对 +0.35 ns）。该 helper 的循环与
parent 源码等价，现有差异属于链接/代码布局级波动；它不是新生产查询路径，不影响
PR-3 的 prefix-map 合并门槛。

## Profile

代表性 CPU/heap profile 使用固定 10 秒采集。parent IPv4 TailHit 为
24.645 us/op、0 alloc，CPU 98.97% 累积于 `FindGeoFeedRow`，主要为
`IPNet.Contains` 和 mask 处理。head 混合数据 PrefixMap 为 75.23 ns/op、0 alloc，
CPU 93.06% 累积于 `GeoFeedIndex.Lookup`，主要为 family lookup 和 map access。
两侧 heap 热点均来自 fixture、索引/trie 构造和 profile 启动，查询热循环无分配。
原始 `.pprof` 只作为本地/CI artifact 保存，不提交仓库。

## 产物大小

产物使用 `-buildvcs=false -trimpath`，并以 `-X` 固定 Version、BuildDate、CommitID，
同时使用 `-ldflags '-w -s'`；Darwin 另加 `-macos=13.0`。

### Darwin arm64，未压缩

| Flavor | parent | head | 变化 |
| --- | ---: | ---: | ---: |
| nexttrace | 30,027,362 B | 30,043,938 B | +16,576 B / +0.0552% |
| nexttrace-tiny | 10,950,674 B | 10,983,794 B | +33,120 B / +0.3024% |
| ntr | 10,934,162 B | 10,983,794 B | +49,632 B / +0.4539% |

### Linux arm64，未压缩 / UPX `-9`

| Flavor | parent | head | 未压缩变化 | UPX 变化 |
| --- | ---: | ---: | ---: | ---: |
| nexttrace | 29,687,968 / 9,693,824 B | 29,753,504 / 9,705,776 B | +0.2207% | +0.1233% |
| nexttrace-tiny | 10,879,136 / 4,074,364 B | 10,879,136 / 4,090,588 B | 0.0000% | +0.3982% |
| ntr | 10,879,136 / 4,074,220 B | 10,879,136 / 4,090,568 B | 0.0000% | +0.4013% |

## 验证

新增回归覆盖：

- 4 列、6+ 列、短行、5 列、坏 CIDR、结构错误、I/O 错误和空文件。
- 最长前缀、重复 prefix 最后一条有效记录覆盖、IPv4-mapped IPv6 和 0 alloc lookup。
- path/mtime/size reload、失败保留、generation、并发装载及不可变快照。
- 国家代码精确小写匹配和未知值回退。
- CLI、REST/WS、service/MCP、FastTrace、nali、MTU 的 DN42 source 固定与保留地址查询。
- MTR legacy/per-hop reset 刷新、旧 generation 取消及结果隔离。

final code head 已通过默认 JSON 与 `nojsonv2` 完整测试、全仓 race、build、vet、
golangci-lint、full/tiny/ntr、Web 前端 Node 测试、module verify/tidy diff、安装脚本
smoke，以及 Linux、Windows、Darwin 现有构建矩阵。Darwin amd64/arm64 release-style
产物的 `LC_BUILD_VERSION` 均为 `minos 13.0`。相同 `nojsonv2` 完整测试的墙钟耗时
为 parent 33.69 秒、final code head 25.52 秒，两侧均通过。

## 平台风险与回退

索引内存随有效 prefix 数量和实际出现的 prefix length 数量增长；没有额外后台
goroutine 或 watcher。path/mtime/size 是锁定的变化检测合同，同尺寸且同 mtime 的
原地内容改写不会触发 reload。失败 reload 会继续使用最后一个成功快照，并把错误
返回给显式装载接口；既有 DN42 查询仍按原合同返回旧数据或空结果。

如需回退，可逆序撤销本 PR 的实现提交。现有导出函数没有删除或改签名；新增
`GeoFeedIndex`、`SourceSession` 与 `LookupIPGeoWithSession` 均为增量 API，不涉及
配置、JSON 或持久数据迁移。
