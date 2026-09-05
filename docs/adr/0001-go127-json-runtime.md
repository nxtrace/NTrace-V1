# ADR 0001：Go 1.27 JSON 运行时

- 状态：接受
- 日期：2026-09-05
- 工具链：Go 1.27.1
- Darwin 最低版本：macOS 13.0

## 背景

Go 1.27 的 `encoding/json` v1 API 默认由新的 v2 实现支撑，并允许通过
`GOEXPERIMENT=nojsonv2` 暂时恢复旧实现。Go 官方说明现有 v1 API 继续受支持，
但迁移时不应依赖完整错误文本；直接使用 `encoding/json/v2` 还涉及额外行为差异。

- [Go 1.27 Release Notes](https://go.dev/doc/go1.27)
- [Go 1.27.1 Release History](https://go.dev/doc/devel/release)
- [JSON v1 to v2 Migration Guide](https://go.dev/doc/jsonv2-migration)

NextTrace 的 REST、WebSocket、MTR、service 与 MCP 输出属于公开合同。发布后端
只有在字节和语义完全一致，且任一关键 benchmark 均无显著超过 1% 的回退时才能切换。

## 决策

1. 项目固定使用 Go 1.27.1，Darwin 正式产物最低支持 macOS 13.0。
2. 源码继续使用 `encoding/json` v1 API，不直接导入 `encoding/json/v2`。
3. 正式发布和 `.cross_compile.sh` 保留 `GOEXPERIMENT=nojsonv2`。
4. CI 永久保留默认 JSON 与 `nojsonv2` 两条测试 lane。
5. Golden 锁定字段名、顺序、`omitempty`、`null`、数字、转义和尾换行；不锁定
   `encoding/json` 的完整错误文本。

## 证据

默认后端和 `nojsonv2` 在相同 fixture 上逐字节通过 REST、WebSocket、
trace/MTR service 响应和 MCP `structuredContent` golden。

Apple M5、Go 1.27.1、`GOMAXPROCS=10`、每组 10 次的 `benchstat` 结果：

| 路径 | `nojsonv2` | 默认后端 | 默认后端变化 |
| --- | ---: | ---: | ---: |
| WebSocket marshal | 524.3 ns/op，416 B，2 allocs | 793.6 ns/op，896 B，5 allocs | +51.37%，p=0.000 |
| WebSocket unmarshal | 2.439 µs/op，656 B，15 allocs | 1.285 µs/op，368 B，3 allocs | -47.33%，p=0.000 |

默认后端的编码路径显著超过 1% 回退门槛，因此不能切换正式发布后端。完整产物、
启动、RSS 和 profile 证据见
[Go 1.27.1 JSON 运行时评估](../performance/go127-json-runtime.md)。

## 影响与回退

- 用户可见 JSON 合同不变；正式产物继续使用已经验证的旧实现。
- 开发者直接执行 `go build` 会使用 Go 1.27 默认后端，CI 会验证其兼容性。
- 若未来 Go 补丁或代码调整消除编码回退，使用同一 golden 和 benchmark 重测；
  达到门槛后，从发布 workflow 与 `.cross_compile.sh` 移除 `GOEXPERIMENT` 即可切换。
- 若默认后端出现合同回归，保留的 `nojsonv2` lane 和发布配置仍是即时回退路径。
