package trace

import (
	"context"
	"errors"
	"log"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
	"golang.org/x/sync/semaphore"

	"github.com/nxtrace/NTrace-core/trace/internal"
	"github.com/nxtrace/NTrace-core/util"
)

type TCPTracerIPv6 struct {
	Config
	wg                  sync.WaitGroup
	res                 Result
	inflightRequest     map[int]chan Hop
	inflightRequestLock sync.RWMutex
	SrcIP               net.IP
	icmp                net.PacketConn
	tcp                 net.PacketConn
	tcpConn             *ipv6.PacketConn
	hopLimitLock        sync.Mutex
	final               atomic.Int32
	sem                 *semaphore.Weighted
}

func (t *TCPTracerIPv6) PrintFunc(ctx context.Context, cancel context.CancelCauseFunc) {
	defer t.wg.Done()

	ttl := t.Config.BeginHop - 1
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		if t.AsyncPrinter != nil {
			t.AsyncPrinter(&t.res)
		}

		// 接收的时候检查一下是不是 3 跳都齐了
		if t.ttlComp(ttl + 1) {
			if t.RealtimePrinter != nil {
				t.RealtimePrinter(&t.res, ttl)
			}
			ttl++
			if ttl == int(t.final.Load()) || ttl >= t.MaxHops {
				cancel(errNaturalDone) // 标记为“自然完成”
				return
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (t *TCPTracerIPv6) ttlComp(ttl int) bool {
	idx := ttl - 1
	t.res.lock.RLock()
	defer t.res.lock.RUnlock()
	return idx < len(t.res.Hops) && len(t.res.Hops[idx]) >= t.NumMeasurements
}

func (t *TCPTracerIPv6) launchTTL(ctx context.Context, ttl int) {
	go func(ttl int) {
		for i := 0; i < t.MaxAttempts; i++ {
			// 若此 TTL 已完成或 ctx 已取消，则不再发起新的尝试
			if t.ttlComp(ttl) || ctx.Err() != nil {
				return
			}

			t.wg.Add(1)
			go func(ttl, i int) {
				if err := t.send(ctx, ttl, i); err != nil && !errors.Is(err, context.Canceled) {
					if util.EnvDevMode {
						panic(err)
					}
					log.Fatal(err)
				}
			}(ttl, i)

			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Millisecond * time.Duration(t.Config.PacketInterval)):
			}
		}
	}(ttl)
}

func (t *TCPTracerIPv6) Execute() (res *Result, err error) {
	// 初始化 inflightRequest map
	t.inflightRequest = make(map[int]chan Hop)

	if len(t.res.Hops) > 0 {
		return &t.res, errTracerouteExecuted
	}

	// 初始化 Result.Hops，并预分配到 MaxHops
	t.res.Hops = make([][]Hop, t.MaxHops)

	// 解析并校验用户指定的 IPv6 源地址
	SrcAddr := net.ParseIP(t.SrcAddr)
	if t.SrcAddr != "" && !util.IsIPv6(SrcAddr) {
		return nil, errors.New("invalid IPv6 SrcAddr: " + t.SrcAddr)
	}
	t.SrcIP, _ = util.LocalIPPortv6(t.DestIP, SrcAddr, "tcp6")
	if t.SrcIP == nil {
		return nil, errors.New("cannot determine local IPv6 address")
	}

	t.tcp, err = net.ListenPacket("ip6:tcp", t.SrcIP.String())
	if err != nil {
		return nil, err
	}
	defer func() {
		if c := t.tcp; c != nil { // 先拷一份引用，避免 defer 执行时 t.tcp 已被并发改写
			_ = c.Close()
		}
	}()
	t.tcpConn = ipv6.NewPacketConn(t.tcp)

	t.icmp, err = icmp.ListenPacket("ip6:ipv6-icmp", t.SrcIP.String())
	if err != nil {
		return &t.res, err
	}
	defer func() {
		if c := t.icmp; c != nil { // 先拷一份引用，避免 defer 执行时 t.icmp 已被并发改写
			_ = c.Close()
		}
	}()

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	ctx, cancel := context.WithCancelCause(sigCtx)
	t.final.Store(-1)

	t.wg.Add(1)
	go t.listenICMP(ctx)
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		internal.ListenTCP(ctx, t.tcp, 6, t.SrcIP, t.DestIP, func(ack uint32, peer net.Addr, ackType int) {
			// 依据报文类型还原原始探测 seq：1=RST+ACK => ack-1-PktSize；2=SYN+ACK => ack-1
			var seq int
			if ackType == 1 {
				seq = int(ack) - 1 - t.Config.PktSize
			} else {
				seq = int(ack) - 1
			}

			// 取出通道后立刻解锁
			t.inflightRequestLock.RLock()
			ch, ok := t.inflightRequest[seq]
			t.inflightRequestLock.RUnlock()
			if !ok || ch == nil {
				return
			}

			h := Hop{
				Success: true,
				Address: peer,
			}

			// 非阻塞发送，避免重复回包把缓冲塞满导致阻塞
			select {
			case ch <- h:
			default:
				// 丢弃重复/迟到的相同 seq 回包，避免阻塞
			}
		})
	}()
	t.wg.Add(1)
	go t.PrintFunc(ctx, cancel)

	t.sem = semaphore.NewWeighted(int64(t.ParallelRequests))

	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		// 立即启动 BeginHop 对应的 TTL 组
		t.launchTTL(ctx, t.BeginHop)

		// 之后按 TTLInterval 周期启动后续 TTL 组
		ticker := time.NewTicker(time.Millisecond * time.Duration(t.Config.TTLInterval))
		defer ticker.Stop()

		for ttl := t.BeginHop + 1; ttl <= t.MaxHops; ttl++ {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			// 如果到达最终跳，则退出
			if f := t.final.Load(); f != -1 && ttl > int(f) {
				return
			}

			// 并发启动这个 TTL 的所有测量
			t.launchTTL(ctx, ttl)
		}
	}()

	<-ctx.Done()
	stop()
	t.wg.Wait()

	bound := int(t.final.Load())
	if bound == -1 {
		bound = t.MaxHops
	}
	t.res.reduce(bound)

	if cause := context.Cause(ctx); !errors.Is(cause, errNaturalDone) {
		return &t.res, cause
	}
	return &t.res, nil
}

func (t *TCPTracerIPv6) listenICMP(ctx context.Context) {
	defer t.wg.Done()
	lc := NewPacketListener(t.icmp)
	go lc.Start(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-lc.Messages:
			if !ok {
				return
			}

			if msg.N == nil {
				continue
			}

			rm, err := icmp.ParseMessage(58, msg.Msg[:*msg.N])
			if err != nil {
				log.Println(err)
				continue
			}

			var data []byte
			switch rm.Type {
			case ipv6.ICMPTypeTimeExceeded:
				body, ok := rm.Body.(*icmp.TimeExceeded)
				if !ok || body == nil {
					continue
				}
				data = body.Data
			case ipv6.ICMPTypeDestinationUnreachable:
				body, ok := rm.Body.(*icmp.DstUnreach)
				if !ok || body == nil {
					continue
				}
				data = body.Data
			default:
				continue
				//log.Println("received icmp message of unknown type", rm.Type)
			}

			if len(data) < 40 || data[0]>>4 != 6 {
				continue
			}

			dstip := net.IP(data[24:40])
			if dstip.Equal(t.DestIP) || dstip.Equal(net.IPv6zero) {
				t.handleICMPMessage(msg, data)
			}
		}
	}
}

func (t *TCPTracerIPv6) handleICMPMessage(msg ReceivedMessage, data []byte) {
	mpls := extractMPLS(msg)

	header, err := util.GetICMPResponsePayload(data)
	if err != nil {
		return
	}

	seq, err := util.GetTCPSeq(header)
	if err != nil {
		return
	}

	// 取出通道后立刻解锁
	t.inflightRequestLock.RLock()
	ch, ok := t.inflightRequest[int(seq)]
	t.inflightRequestLock.RUnlock()
	if !ok || ch == nil {
		return
	}

	h := Hop{
		Success: true,
		Address: msg.Peer,
		MPLS:    mpls,
	}

	// 非阻塞发送，避免重复回包把缓冲塞满导致阻塞
	select {
	case ch <- h:
	default:
		// 丢弃重复/迟到的相同 seq 回包，避免阻塞
	}
}

func (t *TCPTracerIPv6) send(ctx context.Context, ttl, i int) error {
	defer t.wg.Done()
	if t.ttlComp(ttl) {
		// 快路径短路：若该 TTL 已完成，直接返回避免竞争信号量与无谓发包
		return nil
	}

	if err := t.sem.Acquire(ctx, 1); err != nil {
		return err
	}
	defer t.sem.Release(1)

	if f := t.final.Load(); f != -1 && ttl > int(f) {
		return nil
	}

	if t.ttlComp(ttl) {
		// 竞态兜底：获取信号量期间可能已完成，再次检查以避免冗余发包
		return nil
	}

	// 将 TTL 编码到高 8 位；将索引 i 编码到低 24 位
	seq := (ttl << 24) | (i & 0xFFFFFF)

	t.inflightRequestLock.Lock()
	hopCh := make(chan Hop, 1)
	t.inflightRequest[seq] = hopCh
	t.inflightRequestLock.Unlock()
	defer func() {
		t.inflightRequestLock.Lock()
		delete(t.inflightRequest, seq)
		t.inflightRequestLock.Unlock()
	}()

	_, SrcPort := func() (net.IP, int) {
		if !util.RandomPortEnabled() && t.SrcPort > 0 {
			return nil, t.SrcPort
		}
		return util.LocalIPPortv6(t.DestIP, t.SrcIP, "tcp6")
	}()

	ipHeader := &layers.IPv6{
		SrcIP:      t.SrcIP,
		DstIP:      t.DestIP,
		HopLimit:   uint8(ttl),
		NextHeader: layers.IPProtocolTCP,
	}

	tcpHeader := &layers.TCP{
		SrcPort: layers.TCPPort(SrcPort),
		DstPort: layers.TCPPort(t.DestPort),
		Seq:     uint32(seq),
		SYN:     true,
		Window:  14600,
	}
	_ = tcpHeader.SetNetworkLayerForChecksum(ipHeader)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	desiredPayloadSize := t.Config.PktSize
	payload := make([]byte, desiredPayloadSize)

	// 设置随机种子
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range payload {
		payload[i] = byte(r.Intn(256))
	}

	// 序列化 TCP 头与 payload 到缓冲区
	if err := gopacket.SerializeLayers(buf, opts, tcpHeader, gopacket.Payload(payload)); err != nil {
		return err
	}

	// 串行设置 HopLimit + 发送，放在同一把锁里保证并发安全
	t.hopLimitLock.Lock()
	if err := t.tcpConn.SetHopLimit(ttl); err != nil {
		t.hopLimitLock.Unlock()
		return err
	}
	start := time.Now()
	if _, err := t.tcp.WriteTo(buf.Bytes(), &net.IPAddr{IP: t.DestIP}); err != nil {
		t.hopLimitLock.Unlock()
		return err
	}
	t.hopLimitLock.Unlock()

	select {
	case <-ctx.Done():
		return context.Canceled
	case h := <-hopCh:
		rtt := time.Since(start)

		if f := t.final.Load(); f != -1 && ttl > int(f) {
			return nil
		}

		if ip := util.AddrIP(h.Address); ip != nil && ip.Equal(t.DestIP) {
			for {
				old := t.final.Load()
				if old != -1 && ttl >= int(old) {
					break
				}
				if t.final.CompareAndSwap(old, int32(ttl)) {
					break
				}
			}
		}

		h.TTL = ttl
		h.RTT = rtt

		_ = h.fetchIPData(t.Config) // 忽略错误，继续添加结果

		t.res.add(h, i, t.NumMeasurements, t.MaxAttempts)
	case <-time.After(t.Timeout):
		if f := t.final.Load(); f != -1 && ttl > int(f) {
			return nil
		}

		h := Hop{
			Success: false,
			Address: nil,
			TTL:     ttl,
			RTT:     0,
			Error:   errHopLimitTimeout,
		}

		t.res.add(h, i, t.NumMeasurements, t.MaxAttempts)
	}
	return nil
}
