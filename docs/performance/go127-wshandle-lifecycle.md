# Go 1.27 WebSocket 客户端生命周期证据

## 范围与结论

本轮只统一出站 `wshandle.WsConn` 及 NextTrace API v3 receiver 的生命周期：

- 每个 managed connection 使用 `context.WithCancelCause` 根 context；唯一 supervisor
  拥有连接 generation、替换、重试、心跳、状态通知和 `Done` 关闭。
- reader/writer 只执行 I/O 并向 supervisor 上报事件；连接等待使用可轮换
  `stateChanged`，删除 20/50 ms polling。
- 保持 54 秒文本 ping。只有当前 generation 的字面量 `pong` 清零计数；连续两个完整
  响应窗口没有 pong 时结束该 generation，并按既有 200 ms/1 s 节奏重连。
- managed `SendMessage` 在提交时绑定 generation；新增的 `RequestMessage` 还将响应绑定到
  具体 request。旧 generation 的请求不会在新连接重放；仍在等待业务响应的请求只通过
  既有 `API Server Error` JSON 路径失败一次。
- NextTrace API v3 按 `MsgReceiveCh` identity 保持单 receiver owner。连接替换期间旧、新
  stream 可分别收尾，同一 stream 不会出现两个消费者。

导出的 `Conn`、`Done`、`MsgSendCh`、`MsgReceiveCh` 和 `ConnMux` 保留；旧结构体字面量和
legacy channel 发送路径继续可用。JSON schema、协议消息、Geo 字段和三 flavor 依赖边界
不变。首帧 64 KiB read limit 属于 PR-6B，不在本轮加入。

## 精确版本与环境

| 项目 | 值 |
| --- | --- |
| parent | `6422ec5b212eeee49ddac1f7942eaa2278c61d82` |
| benchmark/profile source head | `e72134136844451075dffdc034d88513831b9134` |
| 主机 | Apple M5，10 核，32 GB 内存，AC 供电 |
| 系统 | macOS 26.6.2，darwin/arm64 |
| 工具链 | Go 1.27.1，`GOEXPERIMENT=nojsonv2` |
| benchmark | `GOMAXPROCS=10`，每次 1 秒，10 次 |
| profile | `GOMAXPROCS=10`，MTR Snapshot 30 秒 |
| 统计工具 | `benchstat v0.0.0-20260825160852-19be9d8e6c70` |

证据提交只调整本文档和与新实现一致的代码注释，不改变被测 Go 行为、测试 fixture 或
benchmark harness。PR 性能工作流会在 exact head 另存 Linux cross-reference artifact。

## 调用链变化

### 旧路径

连接初始化后由相互独立的连接、发送、接收与 ping goroutine 共同修改 `WsConn`：

`New -> createWsConn -> messageSendHandler / messageReceiveHandler / wsPingHandler`

连接断开后，多个 goroutine 通过共享 channel、锁和 polling 观察状态并尝试收尾或重连。
write job 没有显式 generation，旧连接失败与新连接建立之间存在请求重放或响应错配窗口；
关闭依赖 recover 避免重复关 channel。

### 新路径

managed connection 建立根 context 后启动唯一 supervisor：

`New -> supervisor -> dial generation -> reader/writer events -> supervisor`

supervisor 串行处理 dial、read、write、request cancel、heartbeat、interrupt 和 root cancel。
generation context 结束时先隔离旧 reader/writer，再安排既有固定节奏的重连。可取消 timer
替代轮询；root cancel 负责最终关闭，并等待已登记 worker 与 request cancel callback 退出。

`NextTraceAPIV3GeoIP` 先选择同一个 `WsConn`，等待其连通并确保该 stream 的唯一兼容
receiver，再通过 `RequestMessage(ctx, ip)` 提交。request 与当时 generation 原子绑定，响应
直接交给该 request，不再经过无 generation 的公开 channel/IP pool；同 IP 并发请求按最早
pending job 匹配响应。取消会废弃当前 generation，写失败、读失败和 generation 结束均由
supervisor 结算。旧结构体字面量仍回退到原公开 channel/IP pool 路径。

legacy `MsgSendCh` 写成功后会保留同 generation/IP 的 FIFO marker：其响应仍进入公开
channel，不会误配给之后的 bound request；若 generation 先结束，已成功写出的 marker 静默
清理，不额外生成 API error。writer 在排队 write-result 前通过共享原子状态发布成功结果，
因此断线与 write-result 的选择顺序不会制造伪失败。

v3 wire 只返回 IP，没有 request ID。为避免已取消请求的迟到同 IP 响应命中后续请求，任一
已开始 wire write 的 tracked request 取消时会轮换整个 generation；同 generation 其余
pending request 通过既有 `API Server Error` 各失败一次。尚未开始写的取消仍静默跳过且不
影响连接。该取舍优先保证不返回错误 Geo 数据。

receive backlog 和 pending request/legacy marker 均固定最多 1024 项。消费变慢时 supervisor
暂停读取 reader event，而不是丢弃业务消息；上限触发既有 generation 回收，root/generation
cancel 仍能解除 reader 和 writer。

## Benchmark

parent/head 使用完全相同的 Go 1.27.1 `nojsonv2` harness 各运行 10 次。首次 parent 文件
误用了默认 JSON 后端，已废弃并重新测量；以下只使用校准后的同配置数据：

| Benchmark | parent | source head | 变化 | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| WebSocket JSON marshal | 479.1 ns | 465.9 ns | -2.73% | 416 -> 416 | 2 -> 2 |
| WebSocket JSON unmarshal | 2.418 us | 2.353 us | -2.69% | 656 -> 656 | 15 -> 15 |

两项均由 benchstat 判为显著改善。PR-6A 没有修改 server JSON benchmark 或
`encoding/json` 调用，结果只用于确认完整构建没有回退，不归因于生命周期重构。

全套 harness 还覆盖 GeoFeed、Geo HTTP/cache、MTR、协议 decoder、MTU 和 nali。未修改包
在顺序长跑中呈现双向约 1%–6% 的时间变化，所有稳定分配合同保持一致；这些变化与本 PR
调用链无关，不作为改善或回退结论。本轮没有规定独立的性能提升阈值。

## Profile

仓库现有 profile harness 不包含 `wshandle` lifecycle benchmark，因此 30 秒 MTR Snapshot
profile 只作为全局交叉回归，不能解释为 supervisor 热点分析。parent/head 的 heap
alloc-space 均全部集中到 `trace.cloneMTRStats`；CPU top 均为 Darwin runtime 调度、GC 和
系统等待函数，没有新增业务热点。

| MTR Snapshot benchmark median | parent | source head |
| --- | ---: | ---: |
| ns/op | 6.126 us | 6.059 us |
| B/op | 49,152 | 49,152 |
| allocs/op | 257 | 257 |

## 产物大小

Darwin arm64 产物使用 `-buildvcs=false -trimpath -ldflags '-s -w -buildid='`；两侧均为
Go 1.27.1、`nojsonv2`，Darwin 不执行 UPX。

| Flavor | parent | source head | 变化 |
| --- | ---: | ---: | ---: |
| nexttrace | 30,523,650 B | 30,110,162 B | -413,488 B / -1.3546% |
| nexttrace-tiny | 11,446,770 B | 11,050,018 B | -396,752 B / -3.4661% |
| ntr | 11,446,770 B | 11,050,018 B | -396,752 B / -3.4661% |

## 验证

`synctest` 与普通测试覆盖：

- 首次连接、200 ms/1 s retry、parent cancel、interrupt、读写失败和幂等 shutdown；
- 54 秒 ping、两个完整缺失 pong 窗口、字面量/非字面量/stale-generation pong；
- generation 替换唤醒、旧 write 不重放、API error 单次投递及响应/写结果竞态；
- 同 IP 旧 generation 响应与全局连接 handoff 不会完成新 request；
- legacy channel 与 bound request 混用时，同 IP 响应仍按提交顺序隔离；
- request context 取消并轮换 generation、已排队取消不写 wire、cancel callback 全部 join；
- 1024 项 receive backlog 的无丢失、顺序与慢消费者关闭；
- 同 stream 单 receiver、连接 handoff、旧/新 stream 隔离及 v3 总 timeout 预算；
- 同步/异步 token cache、FastIP 日志和 dev-mode panic 兼容行为。

source head 已通过定向普通/race 测试、100 次常规压力、不同 `GOMAXPROCS` 的重复测试，
以及 Go 1.27.1 `nojsonv2` 全仓测试。预热构建缓存后的全仓测试墙钟为 parent 24.67 秒、
source head 16.74 秒，峰值 RSS 分别约 445 MB、447 MB；只记录完成耗时，不作性能改善
结论。证据提交后的 exact-head 仍须通过默认 JSON/nojsonv2、全仓 race、build、vet、lint、
三 flavor、前端测试、module 检查与跨平台矩阵后才允许合并。

## 平台风险与回退

主要风险是 generation 边界、响应先于 write result、慢消费者 backpressure、关闭期间的
cancel callback 交错，以及单个 bound request 取消会使同 generation 的其他 pending request
失败一次。所有连接状态只由 supervisor 写入，wire I/O 仍各自单 owner；race 与 synctest
覆盖上述交错。Darwin 最低版本保持 macOS 13.0，没有新增平台 API。

如需回退，可撤销生命周期实现、合同测试和证据提交。没有配置、JSON、协议、持久数据或
既有导出 API 迁移；`RequestMessage` 与 unsupported sentinel 都是增量接口。原始 benchmark、
profile 和二进制不入库，由 CI artifact 保存。
