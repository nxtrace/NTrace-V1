# Go 1.27.1 默认 PGO 评估

## 结论

不提交 `default.pgo`。候选 profile 让三个综合 workload 的等权几何均值改善
5.59%，但 TCP decoder、Geo cache、MTR snapshot 和 preview 均出现统计显著且
超过 1% 的回退，违反合并门槛。

保留 workload、profile 生成脚本和对照脚本，便于 Go 工具链或热点分布变化后复测。

## 环境与 workload

- 基线提交：`954267663dc9daeb70b80f2d3da7907af2bf9ff7`
- 主机：Apple M5，10 核，32 GB；macOS 26.6.2；AC 供电
- 工具：Go 1.27.1，`GOEXPERIMENT=nojsonv2`，`GOMAXPROCS=10`
- benchstat：`golang.org/x/perf` `19be9d8e6c70`
- UPX：5.2.1，`--force-macos -9`
- 固定种子：`20260905`

单一复合 workload 由三个等长阶段组成，每段采集 10 秒 CPU profile：

1. IPv4/IPv6 ICMP、TCP、UDP 纯 decoder。
2. fake prober 生成 64 TTL × 4 path，经过 MTR 聚合、fake Geo provider
   直接/缓存路径与 `encoding/json` 输出。
3. WebSocket envelope 编码和请求解码。

三段 profile 使用 `go tool pprof -proto` 合并。候选 profile SHA-256 为
`4d3d8582e063dc3d893f9f398ec601d55966c5ac6c00666695475e03527fb3a5`。

## Benchmark

PGO off/on 各执行 10 次、每次至少 1 秒。等权综合值使用三个 workload
`ns/op` 中位数比值的几何均值。

| 综合 workload | PGO off | PGO on | 变化 |
| --- | ---: | ---: | ---: |
| Protocol decoder | 371.8 ns/op | 363.6 ns/op | -2.22%，p=0.000 |
| MTR + Geo JSON | 259.9 µs/op | 242.9 µs/op | -6.54%，p=0.000 |
| WebSocket JSON | 2.879 µs/op | 2.651 µs/op | -7.90%，p=0.004 |
| 等权几何均值 | — | — | **-5.59%** |

三个 workload 的 B/op 与 allocs/op 均无显著变化。

关键 guardrail：

| 路径 | PGO 变化 | 判定 |
| --- | ---: | --- |
| ICMP decoder IPv4 / IPv6 | -3.39% / -1.72% | 改善，p≤0.006 |
| TCP decoder IPv4 / IPv6 | +5.07% / +4.77% | **回退，均 p=0.000** |
| UDP decoder IPv4 / IPv6 | 无显著变化 / -0.30% | 通过 |
| Geo cache hit / miss | +3.21% / +3.96% | **回退，均 p=0.000** |
| Geo cache eviction / parallel | +5.21% / 无显著变化 | **eviction 回退，p=0.000** |
| Geo cached lookup hit | +1.48% | **回退，p=0.000** |
| Geo parallel lookup hit | -1.45% | 改善，p=0.018 |
| MTR Update | 无显著变化 | 通过 |
| MTR Snapshot | +3.41% | **回退，p=0.000** |
| MTR preview | +2.30% | **回退，p=0.000** |
| WebSocket marshal / unmarshal | -10.42% / -5.72% | 改善，均 p=0.000 |

所有 guardrail 的 B/op 与 allocs/op 均未变化。回退已经统计明确，不需要增加到
20 次。

## Darwin 产物

两侧使用相同 macOS 13.0 deployment target、
`-buildvcs=false -trimpath -ldflags '-s -w -buildid= -macos=13.0'` 和 UPX 参数。
六个产物的 `LC_BUILD_VERSION` 均为 `minos 13.0`。

| Flavor | PGO off 未压缩 / UPX | PGO on 未压缩 / UPX | 未压缩变化 | UPX 变化 |
| --- | ---: | ---: | ---: | ---: |
| nexttrace | 30,143,154 / 10,158,096 B | 30,192,674 / 10,174,480 B | +0.16% | +0.16% |
| nexttrace-tiny | 11,066,466 / 4,276,240 B | 11,149,026 / 4,309,008 B | +0.75% | +0.77% |
| ntr | 11,066,466 / 4,276,240 B | 11,149,026 / 4,309,008 B | +0.75% | +0.77% |

## `--help` 启动与峰值 RSS

每个新构建产物无预热运行 10 次。“首次启动”记录新产物第一次执行；“后续中位数”
取其余 9 次的中位数；RSS 为 10 次 `/usr/bin/time -l` 的最大观测值。首次执行受
macOS 首次验证影响，只作记录。

| Flavor | PGO off 首次 / 后续中位数 | PGO on 首次 / 后续中位数 | PGO off / on 最大 RSS |
| --- | ---: | ---: | ---: |
| nexttrace | 878.807 / 17.003 ms | 733.432 / 16.880 ms | 29,818,880 / 30,130,176 B |
| nexttrace-tiny | 391.338 / 15.721 ms | 396.602 / 15.705 ms | 23,625,728 / 23,412,736 B |
| ntr | 391.187 / 15.553 ms | 425.306 / 15.792 ms | 23,543,808 / 23,314,432 B |

启动和 RSS 波动没有改变 NO-GO 结论；后续启动中位数的最大变化为 ntr +1.54%，
最大 RSS 的最大变化为 nexttrace +1.04%。

## 复现

profile 与 benchmark：

```sh
scripts/perf/generate_pgo_profile.sh pr8b-9542676
scripts/perf/run_pgo_benchmarks.sh pr8b-9542676-pgo-off off
scripts/perf/run_pgo_benchmarks.sh pr8b-9542676-pgo-on .cache/perf/pr8b-9542676.candidate.pgo
go tool benchstat .cache/perf/pr8b-9542676-pgo-off.workload.bench.txt .cache/perf/pr8b-9542676-pgo-on.workload.bench.txt
go tool benchstat .cache/perf/pr8b-9542676-pgo-off.guardrail.bench.txt .cache/perf/pr8b-9542676-pgo-on.guardrail.bench.txt
```

Darwin 产物需同时设置 `MACOSX_DEPLOYMENT_TARGET=13.0`、SDK 对应的
`CGO_CFLAGS` / `CGO_LDFLAGS`、上述 linker 参数和 `PERF_BINARY_DIR`，然后运行
`measure_binaries.sh`。启动/RSS 使用 `measure_help_startup.sh`。

原始 benchmark、profile 和二进制位于忽略的 `.cache/perf`，不提交候选
`default.pgo`。未来复测必须先提交 workload，再生成与精确提交对应的新 profile。
