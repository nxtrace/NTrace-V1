# ADR 0002：Go 1.27 默认 PGO

- 状态：接受
- 日期：2026-09-05
- 工具链：Go 1.27.1
- 决策：不提交 `default.pgo`

## 背景

Go 可以自动使用主包目录中的 `default.pgo`，也可以通过 `-pgo=off` 显式禁用。
profile 应来自有代表性的稳定 workload，并同时验证没有关键路径回退。

- [Profile-guided optimization](https://go.dev/doc/pgo)

本轮门槛为：三个综合 workload 的等权 CPU 表现显著改善至少 3%，且任一关键
benchmark 均不得显著回退超过 1%。

## 决策

1. 不向仓库加入 `default.pgo`，发布构建继续不启用 PGO。
2. 保留固定 fake prober/provider（含直接和缓存路径）、协议 decoder、MTR/Geo JSON
   与 WebSocket JSON 组成的复合 workload，以及 profile、benchmark、大小和启动测量脚本。
3. 候选 CPU profile、原始 benchmark 和二进制只作为测量产物保存，不进入 Git。

## 证据

Apple M5、Go 1.27.1、`GOMAXPROCS=10`、`nojsonv2` 下，PGO 让三个 workload
等权几何均值改善 6.58%，达到综合门槛；但同时产生以下显著回退：

- TCP decoder IPv4 +6.40%，IPv6 +6.59%。
- Geo cache hit +2.72%，miss +3.18%，cached lookup hit +5.03%。
- MTR snapshot +3.36%。

任一项均足以否决默认 PGO。完整 benchstat、产物大小、启动和 RSS 数据见
[Go 1.27.1 默认 PGO 评估](../performance/go127-default-pgo.md)。

## 影响与复评

- CLI、协议、JSON 与构建 flavor 合同均不变。
- 仓库没有 `default.pgo` 时，Go 的自动 PGO 不会改变正式产物；紧急排除 PGO 时仍可
  显式传 `-pgo=off`。
- Go 补丁版本、热点分布或 profile workload 变化后，可按保留脚本重新采样；只有
  同时满足综合收益和全部 guardrail，才重新评估提交 `default.pgo`。
