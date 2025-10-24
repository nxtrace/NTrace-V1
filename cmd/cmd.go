package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/akamensky/argparse"
	"github.com/fatih/color"
	"github.com/syndtr/gocapability/capability"

	"github.com/nxtrace/NTrace-core/assets/windivert"
	"github.com/nxtrace/NTrace-core/config"
	fastTrace "github.com/nxtrace/NTrace-core/fast_trace"
	"github.com/nxtrace/NTrace-core/ipgeo"
	"github.com/nxtrace/NTrace-core/printer"
	"github.com/nxtrace/NTrace-core/reporter"
	"github.com/nxtrace/NTrace-core/server"
	"github.com/nxtrace/NTrace-core/trace"
	"github.com/nxtrace/NTrace-core/tracelog"
	"github.com/nxtrace/NTrace-core/tracemap"
	"github.com/nxtrace/NTrace-core/util"
	"github.com/nxtrace/NTrace-core/wshandle"
)

type listenInfo struct {
	Binding string
	Access  string
}

func buildListenInfo(addr string) listenInfo {
	effective := addr
	if effective == "" {
		effective = ":1080"
	}

	host, port, err := net.SplitHostPort(effective)
	if err != nil {
		if strings.HasPrefix(effective, ":") {
			host = ""
			port = strings.TrimPrefix(effective, ":")
		} else {
			return listenInfo{
				Binding: effective,
			}
		}
	}

	if port == "" {
		port = "1080"
	}

	rawHost := host
	if rawHost == "" {
		rawHost = "0.0.0.0"
	}

	bindingHost := rawHost
	if strings.Contains(bindingHost, ":") && !strings.HasPrefix(bindingHost, "[") {
		bindingHost = "[" + bindingHost + "]"
	}

	info := listenInfo{
		Binding: fmt.Sprintf("http://%s:%s", bindingHost, port),
	}

	if host == "" || rawHost == "0.0.0.0" || rawHost == "::" {
		guess := guessLocalIPv4()
		if guess != "" {
			if strings.Contains(guess, ":") && !strings.HasPrefix(guess, "[") {
				guess = "[" + guess + "]"
			}
			info.Access = fmt.Sprintf("http://%s:%s", guess, port)
		}
	}

	return info
}

func guessLocalIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, address := range addrs {
			if ipNet, ok := address.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				if ip4 := ipNet.IP.To4(); ip4 != nil {
					return ip4.String()
				}
			}
		}
	}
	return "127.0.0.1"
}

func Execute() {
	parser := argparse.NewParser("nexttrace", "An open source visual route tracking CLI tool")
	// Create string flag
	init := parser.Flag("", "init", &argparse.Options{Help: "Windows ONLY: Extract WinDivert runtime to current directory"})
	ipv4Only := parser.Flag("4", "ipv4", &argparse.Options{Help: "Use IPv4 only"})
	ipv6Only := parser.Flag("6", "ipv6", &argparse.Options{Help: "Use IPv6 only"})
	tcp := parser.Flag("T", "tcp", &argparse.Options{Help: "Use TCP SYN for tracerouting (default dest-port is 80)"})
	udp := parser.Flag("U", "udp", &argparse.Options{Help: "Use UDP SYN for tracerouting (default dest-port is 33494)"})
	fast_trace := parser.Flag("F", "fast-trace", &argparse.Options{Help: "One-Key Fast Trace to China ISPs"})
	port := parser.Int("p", "port", &argparse.Options{Help: "Set the destination port to use. With default of 80 for \"tcp\", 33494 for \"udp\""})
	icmpMode := parser.Int("", "icmp-mode", &argparse.Options{Help: "Windows ONLY: Choose the method to listen for ICMP packets (1=Socket, 2=PCAP; 0=Auto)"})
	numMeasurements := parser.Int("q", "queries", &argparse.Options{Default: 3, Help: "Set the number of probes per each hop"})
	parallelRequests := parser.Int("", "parallel-requests", &argparse.Options{Default: 18, Help: "Set ParallelRequests number. It should be 1 when there is a multi-routing"})
	maxHops := parser.Int("m", "max-hops", &argparse.Options{Default: 30, Help: "Set the max number of hops (max TTL to be reached)"})
	maxAttempts := parser.Int("", "max-attempts", &argparse.Options{Help: "Set the max number of attempts per TTL (instead of a fixed auto value)"})
	dataOrigin := parser.Selector("d", "data-provider", []string{"IP.SB", "ip.sb", "IPInfo", "ipinfo", "IPInsight", "ipinsight", "IPAPI.com", "ip-api.com", "IPInfoLocal", "ipinfolocal", "chunzhen", "LeoMoeAPI", "leomoeapi", "ipdb.one", "disable-geoip"}, &argparse.Options{Default: "LeoMoeAPI",
		Help: "Choose IP Geograph Data Provider [IP.SB, IPInfo, IPInsight, IP-API.com, IPInfoLocal, CHUNZHEN, disable-geoip]"})
	powProvider := parser.Selector("", "pow-provider", []string{"api.nxtrace.org", "sakura"}, &argparse.Options{Default: "api.nxtrace.org",
		Help: "Choose PoW Provider [api.nxtrace.org, sakura] For China mainland users, please use sakura"})
	norDNS := parser.Flag("n", "no-rdns", &argparse.Options{Help: "Do not resolve IP addresses to their domain names"})
	alwaysrDNS := parser.Flag("a", "always-rdns", &argparse.Options{Help: "Always resolve IP addresses to their domain names"})
	routePath := parser.Flag("P", "route-path", &argparse.Options{Help: "Print traceroute hop path by ASN and location"})
	report := parser.Flag("r", "report", &argparse.Options{Help: "output using report mode"})
	dn42 := parser.Flag("", "dn42", &argparse.Options{Help: "DN42 Mode"})
	output := parser.Flag("o", "output", &argparse.Options{Help: "Write trace result to file (RealTimePrinter ONLY)"})
	tablePrint := parser.Flag("t", "table", &argparse.Options{Help: "Output trace results as table"})
	rawPrint := parser.Flag("", "raw", &argparse.Options{Help: "An Output Easy to Parse"})
	jsonPrint := parser.Flag("j", "json", &argparse.Options{Help: "Output trace results as JSON"})
	classicPrint := parser.Flag("c", "classic", &argparse.Options{Help: "Classic Output trace results like BestTrace"})
	beginHop := parser.Int("f", "first", &argparse.Options{Default: 1, Help: "Start from the first_ttl hop (instead of 1)"})
	disableMaptrace := parser.Flag("M", "map", &argparse.Options{Help: "Disable Print Trace Map"})
	disableMPLS := parser.Flag("e", "disable-mpls", &argparse.Options{Help: "Disable MPLS"})
	ver := parser.Flag("V", "version", &argparse.Options{Help: "Print version info and exit"})
	srcAddr := parser.String("s", "source", &argparse.Options{Help: "Use source address src_addr for outgoing packets"})
	srcPort := parser.Int("", "source-port", &argparse.Options{Help: "Use source port src_port for outgoing packets"})
	srcDev := parser.String("D", "dev", &argparse.Options{Help: "Use the following Network Devices as the source address in outgoing packets"})
	deployListen := parser.String("", "listen", &argparse.Options{Help: "Set listen address for web console (e.g. 127.0.0.1:30080)"})
	deploy := parser.Flag("", "depoly", &argparse.Options{Help: "Start the Gin powered web console"})
	//router := parser.Flag("R", "route", &argparse.Options{Help: "Show Routing Table [Provided By BGP.Tools]"})
	packetInterval := parser.Int("z", "send-time", &argparse.Options{Default: 50, Help: "Set how many [milliseconds] between sending each packet. Useful when some routers use rate-limit for ICMP messages"})
	ttlInterval := parser.Int("i", "ttl-time", &argparse.Options{Default: 50, Help: "Set how many [milliseconds] between sending packets groups by TTL. Useful when some routers use rate-limit for ICMP messages"})
	timeout := parser.Int("", "timeout", &argparse.Options{Default: 1000, Help: "The number of [milliseconds] to keep probe sockets open before giving up on the connection"})
	packetSize := parser.Int("", "psize", &argparse.Options{Default: 52, Help: "Set the payload size"})
	str := parser.StringPositional(&argparse.Options{Help: "IP Address or domain name"})
	dot := parser.Selector("", "dot-server", []string{"dnssb", "aliyun", "dnspod", "google", "cloudflare"}, &argparse.Options{
		Help: "Use DoT Server for DNS Parse [dnssb, aliyun, dnspod, google, cloudflare]"})
	lang := parser.Selector("g", "language", []string{"en", "cn"}, &argparse.Options{Default: "cn",
		Help: "Choose the language for displaying [en, cn]"})
	file := parser.String("", "file", &argparse.Options{Help: "Read IP Address or domain name from file"})
	noColor := parser.Flag("C", "no-color", &argparse.Options{Help: "Disable Colorful Output"})
	from := parser.String("", "from", &argparse.Options{Help: "Run traceroute via Globalping (globalping.io) from a specified location. The location field accepts continents, countries, regions, cities, ASNs, ISPs, or cloud regions."})

	err := parser.Parse(os.Args)
	if err != nil {
		// In case of error print error and print usage
		// This can also be done by passing -h or --help flags
		fmt.Print(parser.Usage(err))
		return
	}

	if *noColor {
		color.NoColor = true
	} else {
		color.NoColor = false
	}

	if !*jsonPrint {
		printer.Version()
	}

	if *ver {
		printer.CopyRight()
		os.Exit(0)
	}

	if *deploy {
		capabilitiesCheck()
		// 优先使用 CLI 参数，其次使用环境变量
		listenAddr := *deployListen
		if listenAddr == "" {
			listenAddr = util.EnvDeployAddr
		}
		info := buildListenInfo(listenAddr)
		// 判断是否同时未通过 CLI 和环境变量指定地址
		if *deployListen == "" && util.EnvDeployAddr == "" {
			if info.Access != "" {
				fmt.Printf("启动 NextTrace Web 控制台，监听地址: %s\n", info.Access)
			} else {
				fmt.Printf("启动 NextTrace Web 控制台，监听地址: %s\n", info.Binding)
			}
		} else {
			fmt.Printf("启动 NextTrace Web 控制台，监听地址: %s\n", info.Binding)
			if info.Access != "" && info.Access != info.Binding {
				fmt.Printf("如需远程访问，请尝试: %s\n", info.Access)
			}
		}
		fmt.Println("注意：Web 控制台的安全性有限，请在确保安全的前提下使用，如有必要请使用ACL等方式加强安全性")
		if err := server.Run(listenAddr); err != nil {
			if util.EnvDevMode {
				panic(err)
			}
			log.Fatal(err)
		}
		return
	}

	OSType := 3
	switch runtime.GOOS {
	case "darwin":
		OSType = 1
	case "windows":
		OSType = 2
	}

	if *init && OSType == 2 {
		if err := windivert.PrepareWinDivertRuntime(); err != nil {
			if util.EnvDevMode {
				panic(err)
			}
			log.Fatal(err)
		}
		fmt.Println("WinDivert runtime is ready.")
		return
	}

	if *port == 0 {
		if *udp {
			*port = 33494
		} else {
			*port = 80
		}
	}

	if *maxAttempts > 255 {
		fmt.Println("MaxAttempts 最大值为 255，已自动调整为 255")
		*maxAttempts = 255
	}

	domain := *str

	// 仅在使用 UDP 探测时，确保 UDP 负载长度 ≥ 2
	if *udp && *packetSize < 2 {
		fmt.Println("UDP 模式下，数据包长度不能小于 2，已自动调整为 2")
		*packetSize = 2
	}

	var m trace.Method
	switch {
	case *tcp:
		m = trace.TCPTrace
	case *udp:
		m = trace.UDPTrace
	default:
		m = trace.ICMPTrace
	}

	if *from != "" && (*fast_trace || *file != "") {
		var paramsFastTrace = fastTrace.ParamsFastTrace{
			OSType:         OSType,
			ICMPMode:       *icmpMode,
			SrcDev:         *srcDev,
			SrcAddr:        *srcAddr,
			DstPort:        *port,
			BeginHop:       *beginHop,
			MaxHops:        *maxHops,
			RDNS:           !*norDNS,
			AlwaysWaitRDNS: *alwaysrDNS,
			Lang:           *lang,
			PktSize:        *packetSize,
			Timeout:        time.Duration(*timeout) * time.Millisecond,
			File:           *file,
			Dot:            *dot,
		}

		fastTrace.FastTest(m, *output, paramsFastTrace)
		if *output {
			fmt.Println("您的追踪日志已经存放在 /tmp/trace.log 中")
		}

		os.Exit(0)
	}

	// DOMAIN处理开始
	if domain == "" {
		fmt.Print(parser.Usage(err))
		return
	}

	if strings.Contains(domain, "/") {
		domain = "n" + domain
		parts := strings.Split(domain, "/")
		if len(parts) < 3 {
			fmt.Println("Invalid input")
			return
		}
		domain = parts[2]
	}

	if strings.Contains(domain, "]") {
		domain = strings.Split(strings.Split(domain, "]")[0], "[")[1]
	} else if strings.Contains(domain, ":") {
		if strings.Count(domain, ":") == 1 {
			domain = strings.Split(domain, ":")[0]
		}
	}
	// DOMAIN处理结束

	capabilitiesCheck()
	// return

	if *dn42 {
		// 初始化配置
		config.InitConfig()
		*dataOrigin = "DN42"
		*disableMaptrace = true
	}

	/**
	 * 此处若使用goroutine同时运行ws的建立与nslookup，
	 * 会导致第一跳的IP信息无法获取，原因不明。
	 */
	//var wg sync.WaitGroup
	//wg.Add(2)
	//
	//go func() {
	//	defer wg.Done()
	//}()
	if strings.EqualFold(*dataOrigin, "LEOMOEAPI") {
		if !strings.EqualFold(*powProvider, "api.nxtrace.org") {
			util.PowProviderParam = *powProvider
		}
		if util.EnvDataProvider != "" {
			*dataOrigin = util.EnvDataProvider
		} else {
			w := wshandle.New()
			w.Interrupt = make(chan os.Signal, 1)
			signal.Notify(w.Interrupt, os.Interrupt)
			defer func() {
				if w.Conn != nil {
					_ = w.Conn.Close()
				}
			}()
		}
	}

	if *from != "" {
		executeGlobalpingTraceroute(
			&trace.GlobalpingOptions{
				Target: *str,
				From:   *from,
				IPv4:   *ipv4Only,
				IPv6:   *ipv6Only,
				TCP:    *tcp,
				UDP:    *udp,
				Port:   port,

				DisableMaptrace: *disableMaptrace,
				DataOrigin:      *dataOrigin,

				TablePrint:   *tablePrint,
				ClassicPrint: *classicPrint,
				RawPrint:     *rawPrint,
				JSONPrint:    *jsonPrint,
			},
			&trace.Config{
				OSType:          OSType,
				DN42:            *dn42,
				NumMeasurements: *numMeasurements,
				Lang:            *lang,
				RDNS:            !*norDNS,
				AlwaysWaitRDNS:  *alwaysrDNS,
				IPGeoSource:     ipgeo.GetSource(*dataOrigin),
				Timeout:         time.Duration(*timeout) * time.Millisecond,
			},
		)
		return
	}

	var ip net.IP
	if *ipv6Only {
		ip, err = util.DomainLookUp(domain, "6", *dot, *jsonPrint)
	} else if *ipv4Only {
		ip, err = util.DomainLookUp(domain, "4", *dot, *jsonPrint)
	} else {
		ip, err = util.DomainLookUp(domain, "all", *dot, *jsonPrint)
	}

	if err != nil {
		if util.EnvDevMode {
			panic(err)
		}
		log.Fatal(err)
	}

	if *srcDev != "" {
		dev, _ := net.InterfaceByName(*srcDev)
		util.SrcDev = dev.Name
		if addrs, err := dev.Addrs(); err == nil {
			for _, addr := range addrs {
				if (addr.(*net.IPNet).IP.To4() == nil) == (ip.To4() == nil) {
					*srcAddr = addr.(*net.IPNet).IP.String()
					// 检查是否是内网IP
					if !(net.ParseIP(*srcAddr).IsPrivate() ||
						net.ParseIP(*srcAddr).IsLoopback() ||
						net.ParseIP(*srcAddr).IsLinkLocalUnicast() ||
						net.ParseIP(*srcAddr).IsLinkLocalMulticast()) {
						// 若不是则跳出
						break
					}
				}
			}
		}
	}

	if !*jsonPrint {
		printer.PrintTraceRouteNav(ip, domain, *dataOrigin, *maxHops, *packetSize, *srcAddr, string(m))
	}

	util.SrcPort = *srcPort
	util.DstIP = ip.String()
	var conf = trace.Config{
		OSType:           OSType,
		ICMPMode:         *icmpMode,
		DN42:             *dn42,
		SrcAddr:          *srcAddr,
		SrcPort:          *srcPort,
		BeginHop:         *beginHop,
		DstIP:            ip,
		DstPort:          *port,
		MaxHops:          *maxHops,
		PacketInterval:   *packetInterval,
		TTLInterval:      *ttlInterval,
		NumMeasurements:  *numMeasurements,
		MaxAttempts:      *maxAttempts,
		ParallelRequests: *parallelRequests,
		Lang:             *lang,
		RDNS:             !*norDNS,
		AlwaysWaitRDNS:   *alwaysrDNS,
		IPGeoSource:      ipgeo.GetSource(*dataOrigin),
		Timeout:          time.Duration(*timeout) * time.Millisecond,
		PktSize:          *packetSize,
	}

	// 暂时弃用
	router := new(bool)
	*router = false
	if !*tablePrint {
		if *classicPrint {
			conf.RealtimePrinter = printer.ClassicPrinter
		} else if *rawPrint {
			conf.RealtimePrinter = printer.EasyPrinter
		} else {
			if *output {
				conf.RealtimePrinter = tracelog.RealtimePrinter
			} else if *router {
				conf.RealtimePrinter = printer.RealtimePrinterWithRouter
				fmt.Println("路由表数据源由 BGP.Tools 提供，在此特表感谢")
			} else {
				conf.RealtimePrinter = printer.RealtimePrinter
			}
		}
	} else {
		if !*report {
			conf.AsyncPrinter = printer.TracerouteTablePrinter
		}
	}

	if *jsonPrint {
		conf.RealtimePrinter = nil
		conf.AsyncPrinter = nil
	}

	if util.Uninterrupted && *rawPrint {
		for {
			_, err := trace.Traceroute(m, conf)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	if *disableMPLS {
		util.DisableMPLS = true
	}

	res, err := trace.Traceroute(m, conf)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			// 用户主动中断：跳过后续的正常收尾
			// os.Exit(130)
			fmt.Println(err)
		}
		return
	}

	if *tablePrint {
		printer.TracerouteTablePrinter(res)
	}

	if *routePath {
		r := reporter.New(res, ip.String())
		r.Print()
	}

	r, err := json.Marshal(res)
	if err != nil {
		fmt.Println(err)
		return
	}
	if !*disableMaptrace &&
		(util.StringInSlice(strings.ToUpper(*dataOrigin), []string{"LEOMOEAPI", "IPINFO", "IPINFO", "IP-API.COM", "IPAPI.COM"})) {
		url, err := tracemap.GetMapUrl(string(r))
		if err != nil {
			fmt.Println(err)
			return
		}
		res.TraceMapUrl = url
		if !*jsonPrint {
			tracemap.PrintMapUrl(url)
		}
	}
	r, err = json.Marshal(res)
	if err != nil {
		fmt.Println(err)
		return
	}
	if *jsonPrint {
		fmt.Println(string(r))
	}
}

func capabilitiesCheck() {
	// Windows 判断放在前面，防止遇到一些奇奇怪怪的问题
	if runtime.GOOS == "windows" {
		// Running on Windows, skip checking capabilities
		return
	}

	uid := os.Getuid()
	if uid == 0 {
		// Running as root, skip checking capabilities
		return
	}

	/***
	* 检查当前进程是否有两个关键的权限
	==== 看不到我 ====
	* 没办法啦
	* 自己之前承诺的坑补全篇
	* 被迫填坑系列 qwq
	==== 看不到我 ====
	***/

	// NewPid 已经被废弃了，这里改用 NewPid2 方法
	caps, err := capability.NewPid2(0)
	if err != nil {
		// 判断是否为macOS
		if runtime.GOOS == "darwin" {
			// macOS下报错有问题
		} else {
			fmt.Println(err)
		}
		return
	}

	// load 获取全部的 caps 信息
	err = caps.Load()
	if err != nil {
		fmt.Println(err)
		return
	}

	// 判断一下权限有木有
	if caps.Get(capability.EFFECTIVE, capability.CAP_NET_RAW) && caps.Get(capability.EFFECTIVE, capability.CAP_NET_ADMIN) {
		// 有权限啦
		return
	} else {
		// 没权限啦
		fmt.Println("您正在以普通用户权限运行 NextTrace，但 NextTrace 未被赋予监听网络套接字的ICMP消息包、修改IP头信息（TTL）等路由跟踪所需的权限")
		fmt.Println("请使用管理员用户执行 `sudo setcap cap_net_raw,cap_net_admin+eip ${your_nexttrace_path}/nexttrace` 命令，赋予相关权限后再运行~")
		fmt.Println("什么？为什么 ping 普通用户执行不要 root 权限？因为这些工具在管理员安装时就已经被赋予了一些必要的权限，具体请使用 `getcap /usr/bin/ping` 查看")
	}
}

func executeGlobalpingTraceroute(opts *trace.GlobalpingOptions, config *trace.Config) {
	res, measurement, err := trace.GlobalpingTraceroute(opts, config)
	if err != nil {
		fmt.Println(err)
		return
	}

	if !opts.DisableMaptrace &&
		(util.StringInSlice(strings.ToUpper(opts.DataOrigin), []string{"LEOMOEAPI", "IPINFO", "IPINFO", "IP-API.COM", "IPAPI.COM"})) {
		r, err := json.Marshal(res)
		if err != nil {
			fmt.Println(err)
			return
		}
		url, err := tracemap.GetMapUrl(string(r))
		if err != nil {
			fmt.Println(err)
			return
		}
		res.TraceMapUrl = url
	}

	if opts.JSONPrint {
		r, err := json.Marshal(res)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println(string(r))
		return
	}

	fmt.Fprintln(color.Output, color.New(color.FgGreen, color.Bold).Sprintf("> %s", trace.GlobalpingFormatLocation(&measurement.Results[0])))

	output := trace.GlobalpingGetFirstOutputLine(&measurement.Results[0])
	if output != "" {
		fmt.Fprintln(color.Output, output)
	}

	if opts.TablePrint {
		printer.TracerouteTablePrinter(res)
	}

	for i := range res.Hops {
		if opts.ClassicPrint {
			printer.ClassicPrinter(res, i)
		} else if opts.RawPrint {
			printer.EasyPrinter(res, i)
		} else {
			printer.RealtimePrinter(res, i)
		}
	}

	tracemap.PrintMapUrl(res.TraceMapUrl)
}
