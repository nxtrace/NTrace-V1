package doctor

import (
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/nxtrace/NTrace-core/config"
)

var labels = map[string][2]string{
	"title":      {"NextTrace 探测环境自检", "NextTrace probe environment check"},
	"basic":      {"基本信息", "Build and platform"},
	"request":    {"请求与选择", "Request and selection"},
	"prediction": {"系统路由预测", "System route prediction"},
	"actual":     {"检查结果", "Check results"},
	"summary":    {"结论", "Conclusion"},
	"version":    {"版本", "Version"}, "platform": {"平台", "Platform"},
	"target": {"目标", "Target"}, "candidates": {"解析候选", "Resolved candidates"},
	"selected": {"选定目标", "Selected target"}, "protocol": {"协议", "Protocol"},
	"port": {"目标端口", "Destination port"}, "source_port": {"请求源端口", "Requested source port"},
	"requested_source": {"请求源地址", "Requested source"}, "requested_device": {"请求接口", "Requested interface"},
	"effective_source": {"选定源地址", "Selected source"}, "effective_device": {"有效设备约束", "Effective device constraint"},
	"source_basis": {"源地址依据", "Source selection basis"},
	"resolver":     {"目标解析器", "Target resolver"}, "system_dns": {"系统 DNS", "System DNS"},
	"tos":        {"请求 TOS（生效未验证）", "Requested TOS (application unverified)"},
	"icmp_mode":  {"请求 ICMP 接收模式", "Requested ICMP receive mode"},
	"conditions": {"查询条件", "Query conditions"}, "limitations": {"预测限制", "Prediction limits"},
	"egress": {"预计出口", "Predicted interface"}, "gateway": {"预计下一跳", "Predicted next hop"},
	"route_source": {"路由返回源地址", "Route source"}, "on_link": {"直连，无网关", "On-link, no gateway"},
	"unknown": {"未知", "Unknown"}, "pass": {"通过", "Pass"}, "fail": {"失败", "Fail"},
	"skip": {"跳过", "Skipped"}, "not_applicable": {"不适用", "Not applicable"},
	"interface": {"请求接口检查", "Requested interface check"}, "resolve": {"目标解析", "Target resolution"},
	"source": {"源地址选择", "Source selection"}, "route": {"系统路由查询", "System route query"},
	"backend":                {"探测后端", "Probe backend"},
	"icmp_socket":            {"ICMP 接收 socket", "ICMP receive socket"},
	"icmp_socket_bind":       {"ICMP socket 创建与绑定", "ICMP socket creation and binding"},
	"tcp_socket_bind":        {"TCP socket 创建与绑定", "TCP socket creation and binding"},
	"udp_socket_bind":        {"UDP socket 创建与绑定", "UDP socket creation and binding"},
	"tcp_capture_filter":     {"TCP 抓包与过滤器", "TCP capture and filter"},
	"udp_capture_filter":     {"UDP 抓包与过滤器", "UDP capture and filter"},
	"windivert_availability": {"WinDivert 接收后端检查", "WinDivert receive backend check"},
	"windivert_icmp_filter":  {"WinDivert ICMP 过滤器", "WinDivert ICMP filter"},
	"windivert_tcp_filter":   {"WinDivert TCP 过滤器", "WinDivert TCP filter"},
	"windivert_tcp_send":     {"WinDivert TCP 发送句柄", "WinDivert TCP send handle"},
	"windivert_udp_send":     {"WinDivert UDP 发送句柄", "WinDivert UDP send handle"},
	"windivert_icmp_send":    {"WinDivert ICMPv6 发送句柄", "WinDivert ICMPv6 send handle"},
	"receiver_selection":     {"ICMP 接收路径选择（收包未验证）", "ICMP receiver selection (reception unverified)"},
	"Socket; WinDivert selection requires administrator privileges":            {"Socket；缺少 WinDivert 模式所需的管理员权限", "Socket; WinDivert selection requires administrator privileges"},
	"Socket; WinDivert availability check failed":                              {"Socket；WinDivert 可用性检查失败", "Socket; WinDivert availability check failed"},
	"Socket alternative checked; normal selection unverified under NO_INSTALL": {"已检查 Socket 备选路径；禁止安装策略下无法确认普通运行的最终选择", "Socket alternative checked; normal selection unverified under NO_INSTALL"},
	"explicit_source": {"显式源地址", "Explicit source"}, "device_source": {"接口地址选择", "Interface address selection"},
	"route_prediction":           {"系统按探测条件选择的地址", "Kernel source selection for the probe route"},
	"socket_prediction":          {"系统为 UDP socket 选择的地址", "Kernel selection for a UDP socket"},
	"optional":                   {"不构成阻断项", "Non-blocking"},
	"complete":                   {"必要检查已完成，未发现初始化阻断项。", "Required checks completed without an initialization blocker."},
	"failed":                     {"发现失败项，详见检查结果。", "Failures found; see check results."},
	"incomplete":                 {"必要检查未能全部确认。", "Some required checks remain unconfirmed."},
	"interrupted":                {"检查已取消，以下为已收集结果。", "Check cancelled; collected results follow."},
	"boundary":                   {"实际发包出口、收发能力、目标可达性：未验证。", "Actual packet egress, send/receive operation and target reachability: unverified."},
	"windows":                    {"Windows 设备参数仅用于源地址选择；WinDivert 检查禁止安装驱动。", "Windows device selection selects a source address; WinDivert checks prohibit driver installation."},
	"IP literal":                 {"IP 地址，无需解析", "IP literal; no DNS query"},
	"target unavailable":         {"目标地址未确定", "Target address unavailable"},
	"source address unavailable": {"源地址未确定", "Source address unavailable"},
	"effective source configuration unavailable":                                                         {"有效源配置未确定", "Effective source configuration unavailable"},
	"source policy, protocol, ports and TOS are not included in this route query":                        {"本次路由查询未包含源地址策略、协议、端口及 TOS", "Source policy, protocol, ports and TOS are not included in this route query"},
	"protocol, ports and TOS are not included; --dev selects a source address, not an interface binding": {"本次查询未包含协议、端口及 TOS；设备参数仅用于源地址选择", "Protocol, ports and TOS are not included; --dev selects a source address, not an interface binding"},
	"source port selected during probing; ECMP prediction may differ":                                    {"源端口在探测时确定，多路径选择可能不同", "Source port selected during probing; ECMP prediction may differ"},
	"raw socket lookup omits transport ports; ECMP prediction may differ":                                {"原始套接字选路不使用传输层端口，多路径选择可能不同", "Raw socket lookup omits transport ports; ECMP prediction may differ"},
}

func textLabel(key, lang string) string {
	if v, ok := labels[key]; ok {
		if lang == "en" {
			return v[1]
		}
		return v[0]
	}
	return key
}

// safeLine prevents terminal control sequences or injected report rows.
func safeLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return ' '
		}
		return r
	}, s)
}

func Render(w io.Writer, r Report) error {
	lang := r.Request.Config.Lang
	l := func(key string) string { return textLabel(key, lang) }
	var b strings.Builder
	field := func(key, value string) {
		if value == "" {
			value = l("unknown")
		}
		_, _ = fmt.Fprintf(&b, "%s: %s\n", l(key), safeLine(value))
	}
	section := func(key string) { _, _ = fmt.Fprintf(&b, "\n%s\n", l(key)) }
	_, _ = fmt.Fprintln(&b, l("title"))
	if r.Interrupted {
		_, _ = fmt.Fprintln(&b, l("interrupted"))
	}
	section("basic")
	field("version", strings.TrimSpace(config.Version+" "+config.CommitID+" "+config.BuildDate))
	field("platform", Platform())
	section("request")
	field("target", r.Request.Target)
	field("protocol", string(r.Request.Method))
	if r.Request.Method != "icmp" {
		field("port", fmt.Sprint(r.Request.Config.DstPort))
		field("source_port", fmt.Sprint(r.Request.Config.SrcPort))
	}
	resolver := r.Request.DotServer
	if resolver == "" {
		resolver = l("system_dns")
	}
	field("resolver", resolver)
	ips := make([]string, 0, len(r.Candidates))
	for _, ip := range r.Candidates {
		ips = append(ips, ip.String())
	}
	field("candidates", strings.Join(ips, ", "))
	target := ""
	if r.Target != nil {
		target = r.Target.String()
	}
	field("selected", target)
	if r.Request.Config.SrcAddr != "" {
		field("requested_source", r.Request.Config.SrcAddr)
	}
	if r.Request.Config.SourceDevice != "" {
		field("requested_device", r.Request.Config.SourceDevice)
	}
	field("effective_source", r.Source)
	if r.SourceBasis != "" {
		field("source_basis", l(r.SourceBasis))
	}
	if r.Device != "" {
		field("effective_device", r.Device)
	}
	field("tos", fmt.Sprint(r.Request.Config.TOS))
	if r.Request.Config.OSType == 2 {
		field("icmp_mode", fmt.Sprint(r.Request.Config.ICMPMode))
		_, _ = fmt.Fprintln(&b, l("windows"))
	}
	section("prediction")
	field("conditions", r.Route.Conditions)
	field("egress", r.Route.Interface)
	gateway := r.Route.Gateway
	if r.Route.OnLink {
		gateway = l("on_link")
	}
	field("gateway", gateway)
	field("route_source", r.Route.Source)
	if r.Route.Limitations != "" {
		field("limitations", l(r.Route.Limitations))
	}
	section("actual")
	for _, c := range r.Checks {
		_, _ = fmt.Fprintf(&b, "[%s] %s", l(string(c.Status)), l(c.Name))
		if c.Detail != "" {
			_, _ = fmt.Fprintf(&b, ": %s", safeLine(l(c.Detail)))
		}
		if c.Optional {
			_, _ = fmt.Fprintf(&b, " (%s)", l("optional"))
		}
		_, _ = fmt.Fprintln(&b)
	}
	section("summary")
	key := "complete"
	if r.ExitCode() == 1 {
		key = "failed"
	} else if r.ExitCode() != 0 {
		key = "incomplete"
	}
	_, _ = fmt.Fprintln(&b, l(key))
	_, _ = fmt.Fprintln(&b, l("boundary"))
	_, err := io.WriteString(w, b.String())
	return err
}
