# Go 1.27 MTR 聚合器优化证据

## 范围与结论

本轮只修改 active trace aggregator，未触碰无生产调用者的
`server/mtr.go` legacy aggregator。TTL 数据改为可增长 slice，bucket 保持首次
观测顺序并使用 comparable identity 索引；快照按版本缓存，preview clone 只在
修改受影响 TTL 时 copy-on-write。

导出的 `MTRAggregator` API、MTR 统计公式、unknown 单路径归并、JSON schema、
CLI/TTY 输出和三 flavor 依赖边界保持不变。同 TTL multipath 顺序固定为首次观测
顺序。正式 10 轮 benchmark 的三个合并门槛全部通过。

## 精确版本与环境

| 项目 | 值 |
| --- | --- |
| parent | `7fb7f633513fec40f71949b20f3314bfa4c24225` |
| benchmark/profile head | `18c7f6a80b5785273d5882e0dca3c280fa6f20fc` |
| 主机 | Apple M5，10 核，32 GB 内存，AC 供电 |
| 系统 | macOS 26.6.2，darwin/arm64 |
| 工具链 | Go 1.27.1，`GOEXPERIMENT=nojsonv2` |
| benchmark | `GOMAXPROCS=10`，每次 1 秒，10 次 |
| profile | `GOMAXPROCS=10`，每个目标 30 秒 |
| 统计工具 | `benchstat v0.0.0-20260825160852-19be9d8e6c70` |

报告提交只增加本文档，不改变被测 Go 源码、测试 fixture 或 benchmark harness。
PR 性能工作流会在 exact head 另存 Linux cross-reference artifact。

## 调用链变化

### Update 与顺序

旧实现先把一轮 attempts 分组到 map，再遍历 map 合并并在每次 Snapshot 时排序。
新实现按输入顺序直接聚合到 `buckets[ttl-1]` 的稳定 rows，并用 identity 到 row
下标的 map 做查找。IP identity 使用 `netip.Addr.Unmap()`，非 IP 地址使用
`Network()` 与 `String()`；unknown 和 host-only identity 保留原语义。

同 TTL 新路径只追加到既有 rows 尾部。metadata patch 只补空字段，不改变统计或
行位置。unknown 仍只在恰好一个已知路径时归并，multipath 下继续保留独立行。

### Snapshot 与 preview

每个 bucket 按 version 缓存不可变统计行，聚合器再按全局 version 缓存 TTL 升序
快照。对外每次仍返回隔离副本，并深复制 `Geo.Router`、MPLS 与非 nil Response，
调用方不能改写后续快照。

`Clone` 只复制 bucket slot、owner 状态和不可变缓存。原聚合器与 clone 随后都把
共享 bucket 视为只读；Update、PatchMetadata 和 MigrateStats 首次改写某个 TTL
时只复制该 bucket。Reset 可复用外层 slice 容量，但不会改写已发布快照或 clone。

## Benchmark

parent 与 head 使用同一 harness 各运行 10 次，结果均由 benchstat 判为显著：

| Benchmark | parent | head | 变化 |
| --- | ---: | ---: | ---: |
| Update 64x4 | 80.68 us | 44.19 us | -45.22% |
| Clone 64x4 | 36.838 us | 0.407 us | -98.90% |
| Snapshot 64x4 | 26.678 us | 5.990 us | -77.55% |
| preview Clone+Update 64x4 | 67.54 us | 11.33 us | -83.22% |

| Benchmark | parent B/op | head B/op | 变化 | parent allocs/op | head allocs/op | 变化 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Update 64x4 | 225,328 | 143,360 | -36.38% | 1,866 | 834 | -55.31% |
| Clone 64x4 | 121,200 | 3,408 | -97.19% | 901 | 4 | -99.56% |
| Snapshot 64x4 | 106,544 | 49,152 | -53.87% | 458 | 257 | -43.89% |
| preview Clone+Update 64x4 | 229,600 | 97,008 | -57.75% | 1,381 | 283 | -79.51% |

门槛核验：Snapshot allocs/op 需降低至少 25%，实测降低 43.89%；Snapshot ns/op
需降低至少 15%，实测降低 77.55%；preview B/op 需降低至少 50%，实测降低
57.75%。无需增加到 20 次。

## Profile

30 秒 profile 使用与 benchmark 相同的 fixture：

| 目标 | parent | head |
| --- | ---: | ---: |
| Snapshot ns/op | 26,332 | 5,584 |
| Snapshot B/op / allocs | 106,544 / 458 | 49,152 / 257 |
| preview ns/op | 66,959 | 10,462 |
| preview B/op / allocs | 229,600 / 1,381 | 97,008 / 283 |

parent Snapshot 的 alloc space 主要来自每次重建：`snapshotLocked` 90.62%、
`buildMTRHopStat` 7.44%、稳定排序辅助 1.94%。head 中 bucket 构造与排序已退出热
路径，alloc space 集中到保证调用方隔离的 `cloneMTRStats`。

parent preview 的 `Clone` 占 52.49% alloc space，完整 Snapshot 重建占 42.16%。
head 中直接 Clone 降至 3.52%，仅受影响 TTL 的 `cloneMTRBucket` 为 2.71%；其余
主要分配来自最终对外快照复制。

## 产物大小

Darwin arm64 产物使用
`-buildvcs=false -trimpath -ldflags '-s -w -buildid='`；Darwin 不执行 UPX。

| Flavor | parent | head | 变化 |
| --- | ---: | ---: | ---: |
| nexttrace | 30,093,618 B | 30,110,146 B | +0.055% |
| nexttrace-tiny | 11,016,978 B | 11,016,962 B | -16 B |
| ntr | 11,016,978 B | 11,016,962 B | -16 B |

full 实测增加 16,528 B；tiny/ntr 没有引入新的 WebUI、MCP 或 full-only 依赖。
本轮不把小幅二进制变化单独归因于源码体积或链接布局。

## 验证

parent 与 head 的 `nojsonv2` 完整 Go 测试墙钟时间分别为 24.58 秒和 23.89 秒；
head 默认 JSON 为 23.87 秒。head 还通过：

- 默认 JSON 与 `nojsonv2` 的 `go test -count=1 ./...`。
- `go test -race -count=1 ./...`。
- 新合同测试 100 次重复及定向 race。
- `go build ./...`、`go vet ./...`。
- default/nojsonv2 下 tiny、ntr 专项测试及三 flavor 构建。
- Linux amd64、Windows amd64、Darwin arm64 的三 flavor 构建。
- 三个 Darwin release-style 产物各恰有一个 `LC_BUILD_VERSION minos 13.0`。
- Web 前端 15 项 Node 测试。
- `go mod verify`、空的 `go mod tidy -diff`。
- `golangci-lint v2.13.2 --new-from-rev main`，0 个新增问题。
- `git diff --check` 和独立只读合同审计。

仓库当前的无范围限制 `golangci-lint run` 会报告 78 个既存问题；CI 使用
`only-new-issues`，本 PR 未修改或掩盖这些基线问题。

## 风险与回退

主要风险是 COW ownership 或缓存失效遗漏。测试覆盖 Update、Reset、ClearHop、
ClearAbove、MigrateStats 的 move/merge、PatchMetadata、published Snapshot、Clone
双向隔离、Geo.Router/MPLS/Response 深拷贝和 preview 等价；race 未发现共享写。

如需回退，可撤销实现与合同测试提交。没有配置、JSON、持久数据或导出 API
迁移。原始 benchmark、profile 和二进制不入库，由 CI artifact 保存。
