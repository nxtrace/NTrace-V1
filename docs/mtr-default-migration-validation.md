# MTR 默认模式迁移准备：验证记录

日期：2026-09-06。对照基线：`92e0d4be070c35f74d19f97cbe3d24e5d0c266bf`。
本次实现仍将完整版和 tiny 的 `defaultMTR` 设为 `false`；ntr 保持 `true`。

## tiny 体积

同一台 macOS arm64 主机交叉编译 Linux 版本并原生编译 Darwin 版本。使用 Go 1.27.1、`GOEXPERIMENT=nojsonv2`、`-tags flavor_tiny -trimpath -ldflags '-s -w'`；Linux 设置 `CGO_ENABLED=0`。Darwin 设置 `CGO_ENABLED=1`，C 编译与链接使用 `-mmacosx-version-min=13.0`，Go linker 追加 `-macos=13.0`。未注入发布版本或构建时间。Linux amd64/arm64 使用 UPX 5.2.1 `-9`，mipsle 和 Darwin 不压缩。

| 平台 | 基线字节 | 本次实现字节 | 差值 |
|---|---:|---:|---:|
| Linux amd64 | 11,870,368 | 11,870,368 | 0 |
| Linux arm64 | 11,010,208 | 11,010,208 | 0 |
| Linux mipsle | 12,648,639 | 12,648,639 | 0 |
| Darwin arm64 | 11,082,994 | 11,082,994 | 0 |

| UPX 产物 | 基线字节 | 本次实现字节 | 差值 |
|---|---:|---:|---:|
| Linux amd64 | 4,733,908 | 4,553,524 | -180,384 |
| Linux arm64 | 4,129,916 | 4,132,428 | +2,512 |

规划阶段仅将基线 tiny 的 `enableMTR` 改为 `true`，未压缩体积也均未变化，UPX amd64/arm64 分别增加 624/1,012 字节。本次实现还包含显式传统模式和模式解析准备，因此应使用上表作为本次整体变更的比较。

基线 tiny 二进制已包含 MTR TUI 和调度器符号，原先仅未开放 CLI 参数入口。压缩结果受代码布局、构建信息等影响，不能作为长期体积承诺或运行性能收益；二进制字节数也不等于内存占用。

## 构建与自动测试

以下检查通过，Go 测试中的本机 HTTP/TLS 服务在允许绑定回环端口的环境下运行：

```sh
go build ./...
go test ./...
GOEXPERIMENT=nojsonv2 go test ./...
go test -tags flavor_tiny ./cmd ./server
go test -tags flavor_ntr ./cmd ./server
bash -n scripts/regression/unix.sh
```

新增测试覆盖短长参数、参数顺序、显式模式冲突、三种 flavor 参数能力、未来默认 MTR 的传统输出推断，以及 DNS/测速在执行前拒绝传统模式参数。传统 RAW 固定样本验证成功行 12 列、超时行 8 列，保留现有停止原因输出测试。

## macOS 运行验证

- 完整版和 tiny 均以 `127.0.0.1`、禁用 GeoIP/RDNS、有限次数和跳数验证。归一化 RTT 后，当前默认文本与 `-k`、`--traceroute` 一致；单独 RAW 与 `--traceroute --raw` 一致。
- 两个 flavor 的有限 MTR report/RAW 正常退出；MTR RAW 数据行保持 12 列。
- 短长传统模式参数与 MTR/report/wide、MTU 冲突时，退出码为 1、stdout 为空、stderr 给出冲突；完整版另覆盖 DNS、测速、IP 标注和 deploy。
- 两个 flavor 的真实 PTY 测试验证备用屏幕进入、按 `q` 退出、光标及终端属性恢复。比较终端属性时仅排除 Darwin 内核管理的 `PENDIN` 状态位。
- 使用 Go `-overlay` 仅在临时构建中将完整版和 tiny 的 `defaultMTR` 设为 `true`，验证默认输出和单独 RAW 进入 MTR；显式传统模式、JSON/table/classic、两种文件输出、route-path 和文件目标保持传统路径。MTU 的 `--json --tcp` 进入 MTU 自身的协议冲突检查。ntr 的报告模式和参数能力保持不变。

Linux/Windows 运行回归用例已加入现有 CI 脚本；本机没有执行这些平台的运行验收。没有执行公网全套回归、生产部署或默认模式发布切换。
