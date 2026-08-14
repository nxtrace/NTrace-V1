package ipgeo

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/tidwall/gjson"

	"github.com/nxtrace/NTrace-core/wshandle"
)

/***
 * 原理介绍 By Leo
 * WebSocket 一共开启了一个发送和一个接收协程，在 New 了一个连接的实例对象后，不给予关闭，持续化连接
 * 当有新的IP请求时，一直在等待IP数据的发送协程接收到从 nexttrace_api_v3.go 的 sendNextTraceAPIV3IPRequest 函数发来的IP数据，向服务端发送数据
 * 由于实际使用时有大量并发，但是 ws 在同一时刻每次有且只能处理一次发送一条数据，所以必须给 ws 连接上互斥锁，保证每次只有一个协程访问
 * 运作模型可以理解为一个 Node 一直在等待数据，当获得一个新的任务后，转交给下一个协程，不再关注这个 Node 的下一步处理过程，并且回到空闲状态继续等待新的任务
***/

// IPPool IP 查询池 map - ip - ip channel
type IPPool struct {
	pool    map[string]chan IPGeoData
	poolMux sync.RWMutex
}

var IPPools = IPPool{
	pool: make(map[string]chan IPGeoData),
}

var getNextTraceAPIV3WSConn = wshandle.GetWsConn

func sendNextTraceAPIV3IPRequest(ctx context.Context, wsConn *wshandle.WsConn, ip string) bool {
	if wsConn == nil {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return false
	}
	select {
	case wsConn.MsgSendCh <- ip:
		return true
	case <-ctx.Done():
		return false
	}
}

func receiveNextTraceAPIV3Responses() {
	for {
		// 获得连接实例
		wsConn := getNextTraceAPIV3WSConn()
		if wsConn == nil {
			return
		}
		if !receiveNextTraceAPIV3Conn(wsConn) {
			return
		}
	}
}

func receiveNextTraceAPIV3Conn(wsConn *wshandle.WsConn) bool {
	// 防止多协程抢夺一个ws连接，导致死锁，当一个协程获得ws的控制权后上锁
	wsConn.ConnMux.Lock()
	// 函数退出时解锁，给其他协程使用
	defer wsConn.ConnMux.Unlock()
	for data := range wsConn.MsgReceiveCh {
		dispatchNextTraceAPIV3Message(data)
	}
	return getNextTraceAPIV3WSConn() != wsConn
}

func dispatchNextTraceAPIV3Message(data string) {
	// json解析 -> data
	res := gjson.Parse(data)
	// 根据返回的IP信息，发送给对应等待回复的IP通道上
	var domain = res.Get("domain").String()

	if res.Get("domain").String() == "" {
		domain = res.Get("owner").String()
	}

	m := make(map[string][]string)
	_ = json.Unmarshal([]byte(res.Get("router").String()), &m)

	lat, _ := strconv.ParseFloat(res.Get("lat").String(), 32)
	lng, _ := strconv.ParseFloat(res.Get("lng").String(), 32)

	ip := res.Get("ip").String()
	geo := IPGeoData{
		Asnumber:  res.Get("asnumber").String(),
		Country:   res.Get("country").String(),
		CountryEn: res.Get("country_en").String(),
		Prov:      res.Get("prov").String(),
		ProvEn:    res.Get("prov_en").String(),
		City:      res.Get("city").String(),
		CityEn:    res.Get("city_en").String(),
		District:  res.Get("district").String(),
		Owner:     domain,
		Lat:       lat,
		Lng:       lng,
		Isp:       res.Get("isp").String(),
		Whois:     res.Get("whois").String(),
		Prefix:    res.Get("prefix").String(),
		Router:    m,
	}

	// Safely load (or lazily create) the channel for this IP before sending
	IPPools.poolMux.RLock()
	ch, ok := IPPools.pool[ip]
	IPPools.poolMux.RUnlock()
	if !ok || ch == nil {
		IPPools.poolMux.Lock()
		if IPPools.pool[ip] == nil {
			IPPools.pool[ip] = make(chan IPGeoData, 1)
		}
		ch = IPPools.pool[ip]
		IPPools.poolMux.Unlock()
	}
	deliverGeo(ch, geo)
}

func deliverGeo(ch chan IPGeoData, geo IPGeoData) {
	select {
	case ch <- geo:
		return
	default:
	}
	select {
	case <-ch:
	default:
	}
	select {
	case ch <- geo:
	default:
	}
}

// 当前的实现中，每次调用 receiveNextTraceAPIV3Responses() 都会锁定 WebSocket 连接
// 当前为单例模式，只启动一个 NextTrace API v3 接收协程

var (
	nextTraceAPIV3ReceiveMu      sync.Mutex
	nextTraceAPIV3ReceiveRunning bool
	nextTraceAPIV3ReceiveRestart bool
)

func startNextTraceAPIV3Receiver() {
	nextTraceAPIV3ReceiveMu.Lock()
	if nextTraceAPIV3ReceiveRunning {
		nextTraceAPIV3ReceiveRestart = true
		nextTraceAPIV3ReceiveMu.Unlock()
		return
	}
	nextTraceAPIV3ReceiveRunning = true
	nextTraceAPIV3ReceiveRestart = false
	nextTraceAPIV3ReceiveMu.Unlock()

	go runNextTraceAPIV3ReceiveLoop()
}

func runNextTraceAPIV3ReceiveLoop() {
	for {
		receiveNextTraceAPIV3Responses()

		nextTraceAPIV3ReceiveMu.Lock()
		if !nextTraceAPIV3ReceiveRestart {
			nextTraceAPIV3ReceiveRunning = false
			nextTraceAPIV3ReceiveMu.Unlock()
			return
		}
		nextTraceAPIV3ReceiveRestart = false
		nextTraceAPIV3ReceiveMu.Unlock()
	}
}

// NextTraceAPIV3GeoIP queries the NextTrace API v3 WebSocket service.
func NextTraceAPIV3GeoIP(ip string, timeout time.Duration, lang string, maptrace bool) (*IPGeoData, error) {
	// TODO: 根据lang的值请求中文/英文API
	// TODO: 根据maptrace的值决定是否请求经纬度信息
	if timeout < 2*time.Second {
		timeout = 2 * time.Second
	}

	// 确保对应 IP 的通道已存在（读锁快速路径 + 写锁惰性创建）
	IPPools.poolMux.RLock()
	ch, ok := IPPools.pool[ip]
	IPPools.poolMux.RUnlock()
	if !ok || ch == nil {
		IPPools.poolMux.Lock()
		if IPPools.pool[ip] == nil {
			IPPools.pool[ip] = make(chan IPGeoData, 1)
		}
		ch = IPPools.pool[ip]
		IPPools.poolMux.Unlock()
	}
	drainStaleGeo(ch)

	wsConn := getNextTraceAPIV3WSConn()
	if wsConn == nil {
		return &IPGeoData{}, errors.New("TimeOut")
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := wsConn.WaitUntilConnected(waitCtx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return &IPGeoData{}, errors.New("TimeOut")
		}
		return &IPGeoData{}, err
	}

	// 发送请求
	if !sendNextTraceAPIV3IPRequest(waitCtx, wsConn, ip) {
		return &IPGeoData{}, errors.New("TimeOut")
	}

	// 确保 NextTrace API v3 接收协程只启动一次
	startNextTraceAPIV3Receiver()

	// 等待数据返回或超时
	select {
	case res := <-ch:
		return &res, nil
	case <-waitCtx.Done():
		return &IPGeoData{}, errors.New("TimeOut")
	}
}

// LeoIP is kept for source compatibility.
// Deprecated: use NextTraceAPIV3GeoIP.
func LeoIP(ip string, timeout time.Duration, lang string, maptrace bool) (*IPGeoData, error) {
	return NextTraceAPIV3GeoIP(ip, timeout, lang, maptrace)
}

func drainStaleGeo(ch chan IPGeoData) {
	select {
	case <-ch:
	default:
	}
}
