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

// NextTrace API v3 uses the process-wide WsConn supervisor for serialized
// writes and generation-bound request delivery. A receiver is owned by each
// MsgReceiveCh identity so replacing the global connection cannot create two
// consumers for the same stream or move an old response onto a new stream.

// IPPool IP 查询池 map - ip - ip channel
type IPPool struct {
	pool    map[string]chan IPGeoData
	poolMux sync.RWMutex
}

var IPPools = IPPool{
	pool: make(map[string]chan IPGeoData),
}

var getNextTraceAPIV3WSConn = wshandle.GetWsConn
var sendNextTraceAPIV3IPRequestFn = sendNextTraceAPIV3IPRequest

func sendNextTraceAPIV3IPRequest(ctx context.Context, wsConn *wshandle.WsConn, ip string) bool {
	if wsConn == nil {
		return false
	}
	return wsConn.SendMessage(ctx, ip) == nil
}

type nextTraceAPIV3Receiver struct {
	done chan struct{}
}

type nextTraceAPIV3ReceiverOwner struct {
	mu        sync.Mutex
	receivers map[<-chan string]*nextTraceAPIV3Receiver
}

func newNextTraceAPIV3ReceiverOwner() *nextTraceAPIV3ReceiverOwner {
	return &nextTraceAPIV3ReceiverOwner{
		receivers: make(map[<-chan string]*nextTraceAPIV3Receiver),
	}
}

func (o *nextTraceAPIV3ReceiverOwner) ensure(wsConn *wshandle.WsConn) *nextTraceAPIV3Receiver {
	if wsConn == nil || wsConn.MsgReceiveCh == nil {
		return nil
	}
	receiveCh := (<-chan string)(wsConn.MsgReceiveCh)

	o.mu.Lock()
	if receiver := o.receivers[receiveCh]; receiver != nil {
		o.mu.Unlock()
		return receiver
	}
	receiver := &nextTraceAPIV3Receiver{done: make(chan struct{})}
	o.receivers[receiveCh] = receiver
	o.mu.Unlock()

	go o.consume(receiveCh, receiver)
	return receiver
}

func (o *nextTraceAPIV3ReceiverOwner) consume(
	receiveCh <-chan string,
	receiver *nextTraceAPIV3Receiver,
) {
	for data := range receiveCh {
		dispatchNextTraceAPIV3Message(data)
	}

	o.mu.Lock()
	if o.receivers[receiveCh] == receiver {
		delete(o.receivers, receiveCh)
	}
	o.mu.Unlock()
	close(receiver.done)
}

var nextTraceAPIV3Receivers = newNextTraceAPIV3ReceiverOwner()

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

	// Bind the response consumer to the same connection selected above. A
	// concurrent global replacement must not move this request to another
	// connection between readiness, send, and response dispatch.
	nextTraceAPIV3Receivers.ensure(wsConn)

	// 发送请求
	if !sendNextTraceAPIV3IPRequestFn(waitCtx, wsConn, ip) {
		return &IPGeoData{}, errors.New("TimeOut")
	}

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
