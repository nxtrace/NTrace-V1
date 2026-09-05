# Go 1.27 deploy WebSocket 会话生命周期证据

## 范围与结论

本轮只统一 deploy 入站 WebSocket 会话的生命周期：

- init JSON 读取成功后立即建立 `context.WithCancelCause` 根 context；session 统一拥有
  reader、writer、trace worker 和连接关闭。
- 正常完成进入 draining，按 FIFO 排空发送队列后关闭连接；异常完成进入 aborting，取消
  trace、丢弃尚未开始写的消息，再由唯一 writer 发送既有 close frame 并关闭连接。
- slow consumer、reader error、writer error 和 parent cancel 共用幂等终止状态机；删除
  `writeLoop` 的宽泛 panic recovery；trace worker 边界仅将未捕获 panic 转为 1011/internal
  error，避免 panic 越过 Gin recovery 终止进程。
- 会话主动发出的 `WriteJSON`、close frame 和会话期 `Close` 由 writer 串行执行；reader 只调用
  `NextReader`。Gorilla 可能在读调用内自动发送 control frame，此时依赖其对 `WriteControl` 和
  `Close` 的并发安全保证。
- 既有 64 KiB init 首帧上限不改值；新增真实 Gorilla 连接的 65,536/65,537 字节边界测试。

JSON schema、消息顺序、CLI、REST、MCP、三 flavor 依赖边界和导出 API 均不变。

## 精确版本与环境

| 项目 | 值 |
| --- | --- |
| parent | `acfffd84e74c1745b4e10a284979c1facc194439` |
| benchmark/profile source head | `c098446193b2671f5d625af27d6455fb6c5ee781` |
| 主机 | Apple M5，10 核，32 GB 内存，AC 供电 |
| 系统 | macOS 26.6.2，darwin/arm64 |
| 工具链 | Go 1.27.1，`GOEXPERIMENT=nojsonv2` |
| benchmark | `GOMAXPROCS=10`，每次 1 秒；完整 harness 10 次，WS 校准 20 次 |
| profile | `GOMAXPROCS=10`，WS JSON marshal 30 秒 |
| 统计工具 | `benchstat v0.0.0-20260825160852-19be9d8e6c70` |

证据提交只加入本文档，不改变被测 Go 行为、fixture 或 benchmark harness。PR 性能工作流会在
exact head 另存 Linux cross-reference artifact。

## 调用链变化

### 旧路径

`handler -> read init -> detached reader/cancel -> create writer session -> trace on handler stack`

reader goroutine 不属于 session；session 只等待 writer。正常、读错、写错、慢消费者和请求取消
分别修改 channel、context 与连接，`WriteControl`/`Close` 也可能从非 writer 路径执行。
`writeLoop` 依靠 recover 兜住关闭交错。

### 新路径

`handler -> read init -> create session root -> reader/writer workers -> registered trace worker`

session 使用 `open -> draining/aborting -> closed` 状态机：

- `send` 与 `close(sendCh)` 共用状态锁，队列满后先释放锁再请求 abort，不会自锁或
  send-on-closed-channel。
- 正常 `finish` 关闭发送入口，writer 排空队列、取消根 context、关闭连接并解除 reader，最后
  等待所有已登记 worker。
- 异常路径先记录首次 cause 并取消根 context；writer 不再开始写队列尾部，只在当前 write
  返回后串行发送 close frame、关闭连接。
- parent cancel 保持不发送额外 close frame；reader、slow consumer、writer error 分别保持
  1000、1013、1011 及原有 reason。

## Benchmark

parent/source head 先使用完整 Go 1.27.1 `nojsonv2` harness 各顺序运行 10 次。该轮 WS JSON
marshal 显示 `+2.66%`，但本 PR 没有修改 benchmark 或 JSON 编解码路径，且同轮未修改模块也
存在双向漂移。按门槛规则，随后预编译两侧 server test binary，并交替顺序采样 20 次，避免
整套长跑的温度和执行顺序偏差。以下以校准结果作为 WS 判定依据：

| Benchmark | parent | source head | benchstat | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| WebSocket JSON marshal | 473.5 ns | 470.1 ns | 不显著，`p=0.304` | 416 -> 416 | 2 -> 2 |
| WebSocket JSON unmarshal | 2.336 us | 2.358 us | 不显著，`p=0.560` | 656 -> 656 | 15 -> 15 |
| geomean | 1.052 us | 1.053 us | +0.10% | 522.4 -> 522.4 | 5.477 -> 5.477 |

现有 benchmark harness 没有对网络连接生命周期做微基准。该路径以确定性交错、worker join 和
race 证明正确性；WS JSON 只用于确认完整 server 构建没有编解码或分配回退，不归因于本轮
状态机重构。

## Profile

parent/source head 对相同 `BenchmarkWebSocketJSONMarshalEnvelope` 各采集 30 秒 CPU 与 heap
profile。单次读数为 460.0 ns/op 和 469.6 ns/op，不用于门槛判断；20 次交替 benchstat 才是
统计结论。

两侧 CPU top 都由 Darwin runtime wait 与 `encoding/json` 主导；该 profile 不执行会话
生命周期，不能用来判断 session、reader、writer 或终止状态机热点，只作为 JSON 路径的
交叉回归证据。heap alloc-space 构成一致：约 84.6% 来自 `encoding/json.Marshal`，其余来自
benchmark 调用；每次操作仍为 416 B、2 allocs。

## 产物大小与测试耗时

Darwin arm64 产物使用 `-buildvcs=false -trimpath -ldflags '-s -w -buildid='`；两侧均为
Go 1.27.1、`nojsonv2`，Darwin 不执行 UPX。

| Flavor | parent | source head | 变化 |
| --- | ---: | ---: | ---: |
| nexttrace | 30,126,690 B | 30,126,706 B | +16 B / +0.00005% |
| nexttrace-tiny | 11,050,018 B | 11,050,018 B | 0 B |
| ntr | 11,050,018 B | 11,050,018 B | 0 B |

同配置、预热缓存后的 `go test -count=1 ./...`：

| 指标 | parent | source head |
| --- | ---: | ---: |
| 墙钟 | 23.46 s | 22.88 s |
| maximum resident set size | 448,102,400 B | 446,382,080 B |

测试耗时和 RSS 只记录完成成本，不解释为性能改善。

## 验证

`testing/synctest` 与真实 Gorilla 集成测试覆盖：

- 正常 drain 严格保持 `start -> hop -> complete`，并等待 reader、writer、trace 全部退出；
- slow consumer、reader error、writer error、parent cancel 取消 trace 并丢弃尾队列；
- 会话主动发出的 data/close write 最大并发为 1；并发 finish/close 只关闭一次且不混合终态；
- trace worker panic 被限制在 worker 边界，转换为单次 1011/internal error 并完整 join；
- 65,536 字节合法 init 进入 trace，65,537 字节收到 1009 且不会调用 tracer；
- 既有 MTR `path_end -> mtr_raw -> path_end(null) -> complete`、single trace stop reason
  和 provider canonicalization 合同保持不变。

source head 已通过定向测试 100 次、race 压力、默认 JSON/nojsonv2 server 测试、全仓普通与
race 测试、build、vet、diff-aware lint、tiny/ntr 测试与构建、Node 15 项测试、module
verify/tidy，以及 Linux、Windows、Darwin 三平台构建。Darwin 三 flavor 的
`LC_BUILD_VERSION` 均为 macOS 13.0。

仓库当前的无范围限制 `golangci-lint run` 会报告 78 个既存问题；CI 使用
`only-new-issues`，本 PR 的 `--new-from-rev main` 检查为 0 个新增问题。

## 平台风险与回退

主要风险是 normal drain 与 reader/parent cancel 的竞争、blocked write 期间的 abort，以及
`WaitGroup.Go` 登记和最终 `Wait` 的顺序。生产路径只在 handler 调用 `finish` 前登记 trace；
状态锁、可取消根 context、5 秒 write deadline、synctest 与 race 共同覆盖这些边界。

如需回退，可撤销生命周期实现、合同测试和本文档。没有配置、JSON、协议、持久数据或导出
API 迁移；回退不需要数据处理。原始 benchmark、profile、测试日志和二进制不入库，由本地
忽略目录及 CI artifact 保存。
