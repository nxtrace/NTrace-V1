# Go 1.27.1 默认 PGO 评估

## 结论

不提交 `default.pgo`。候选 profile 让三个综合 workload 的等权几何均值改善
6.58%，但 TCP decoder、Geo cache 和 MTR snapshot 均出现统计显著且超过 1%
的回退，违反合并门槛。

保留 workload、profile 生成脚本和对照脚本，便于 Go 工具链或热点分布变化后复测。

## 环境与 workload

- 基线提交：`edfc38cdf6b2baf9928ae2c5f72f8142648aeb9e`
- 主机：Apple M5，10 核，32 GB；macOS 26.6.2；AC 供电
- 工具：Go 1.27.1，`GOEXPERIMENT=nojsonv2`，`GOMAXPROCS=10`
- benchstat：`golang.org/x/perf` `19be9d8e6c70`
- UPX：5.2.1，`--force-macos -9`
- 固定种子：`20260905`

单一复合 workload 由三个等长阶段组成，每段采集 10 秒 CPU profile：

1. IPv4/IPv6 ICMP、TCP、UDP 纯 decoder。
2. fake prober 生成 64 TTL × 4 path，经过 MTR 聚合、fake Geo provider 与
   `encoding/json` 输出。
3. WebSocket envelope 编码和请求解码。

三段 profile 使用 `go tool pprof -proto` 合并。候选 profile SHA-256 为
`6ac6a4c7c72beeaf0662240514a4a6badc882ff887474a8f45dd74396e4fdd1a`。

## Benchmark

PGO off/on 各执行 10 次、每次至少 1 秒。等权综合值使用三个 workload
`ns/op` 中位数比值的几何均值。

| 综合 workload | PGO off | PGO on | 变化 |
| --- | ---: | ---: | ---: |
| Protocol decoder | 369.5 ns/op | 367.2 ns/op | -0.62%，p=0.011 |
| MTR + Geo JSON | 260.3 µs/op | 237.6 µs/op | -8.73%，p=0.000 |
| WebSocket JSON | 2.918 µs/op | 2.623 µs/op | -10.11%，p=0.000 |
| 等权几何均值 | — | — | **-6.58%** |

复合 MTR + Geo JSON 的 B/op 增加 0.54%（p=0.000）；其 allocs/op 与另外两个
workload 的内存指标未变化。

关键 guardrail：

| 路径 | PGO 变化 | 判定 |
| --- | ---: | --- |
| ICMP decoder IPv4 / IPv6 | -1.46% / -1.32% | 改善，均显著 |
| TCP decoder IPv4 / IPv6 | +6.40% / +6.59% | **回退，均 p=0.000** |
| UDP decoder IPv4 / IPv6 | +0.40% / 无显著变化 | 通过 |
| Geo cache hit / miss | +2.72% / +3.18% | **回退，p≤0.001** |
| Geo cache eviction / parallel | 无显著变化 | 通过 |
| Geo cached lookup hit | +5.03% | **回退，p=0.000** |
| Geo parallel lookup hit | 无显著变化 | 通过 |
| MTR Update | -1.68% | 改善，p=0.002 |
| MTR Snapshot | +3.36% | **回退，p=0.002** |
| MTR preview | -0.32% | 通过 |
| WebSocket marshal / unmarshal | -11.51% / -6.16% | 改善，均 p=0.000 |

所有 guardrail 的 B/op 与 allocs/op 均未变化。回退已经统计明确，不需要增加到
20 次。

## Darwin 产物

两侧使用相同 macOS 13.0 deployment target、
`-buildvcs=false -trimpath -ldflags '-s -w -buildid= -macos=13.0'` 和 UPX 参数。
六个产物的 `LC_BUILD_VERSION` 均为 `minos 13.0`。

| Flavor | PGO off 未压缩 / UPX | PGO on 未压缩 / UPX | 未压缩变化 | UPX 变化 |
| --- | ---: | ---: | ---: | ---: |
| nexttrace | 30,143,154 / 10,158,096 B | 30,192,658 / 10,174,480 B | +0.16% | +0.16% |
| nexttrace-tiny | 11,066,466 / 4,276,240 B | 11,132,498 / 4,309,008 B | +0.60% | +0.77% |
| ntr | 11,066,466 / 4,276,240 B | 11,132,498 / 4,309,008 B | +0.60% | +0.77% |

## `--help` 启动与峰值 RSS

每个新构建产物无预热运行 10 次。“首次启动”记录新产物第一次执行；“后续中位数”
取其余 9 次的中位数；RSS 为 10 次 `/usr/bin/time -l` 的最大观测值。首次执行受
macOS 首次验证影响，只作记录。

| Flavor | PGO off 首次 / 后续中位数 | PGO on 首次 / 后续中位数 | PGO off / on 最大 RSS |
| --- | ---: | ---: | ---: |
| nexttrace | 644.691 / 16.910 ms | 519.728 / 16.976 ms | 30,031,872 / 30,031,872 B |
| nexttrace-tiny | 438.096 / 15.803 ms | 438.289 / 15.558 ms | 23,511,040 / 23,478,272 B |
| ntr | 455.425 / 15.459 ms | 449.588 / 15.908 ms | 23,166,976 / 23,658,496 B |

启动和 RSS 没有改变 NO-GO 结论；ntr 后续启动中位数与最大 RSS 还分别增加
2.91% 和 2.12%。

## 复现

profile 与 benchmark：

```sh
scripts/perf/generate_pgo_profile.sh pr8b-edfc38c
scripts/perf/run_pgo_benchmarks.sh pr8b-pgo-off off
scripts/perf/run_pgo_benchmarks.sh pr8b-pgo-on .cache/perf/pr8b-edfc38c.candidate.pgo
go tool benchstat .cache/perf/pr8b-pgo-off.workload.bench.txt .cache/perf/pr8b-pgo-on.workload.bench.txt
go tool benchstat .cache/perf/pr8b-pgo-off.guardrail.bench.txt .cache/perf/pr8b-pgo-on.guardrail.bench.txt
```

Darwin 产物需同时设置 `MACOSX_DEPLOYMENT_TARGET=13.0`、SDK 对应的
`CGO_CFLAGS` / `CGO_LDFLAGS`、上述 linker 参数和 `PERF_BINARY_DIR`，然后运行
`measure_binaries.sh`。启动/RSS 使用 `measure_help_startup.sh`。

原始 benchmark、profile 和二进制位于忽略的 `.cache/perf`，不提交候选
`default.pgo`。未来复测必须先提交 workload，再生成与精确提交对应的新 profile。
