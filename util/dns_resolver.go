package util

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────
// Geo DNS Resolver —— 为 GeoIP API / NextTrace API FastIP
// 提供统一的 DNS 解析策略层。
//
// 策略：优先使用 DoT（--dot-server），DoT 失败时
// 自动回退系统 DNS（可用性优先）。
// ──────────────────────────────────────────────────

var (
	geoDotServer   string        // 当前 dot-server 选项（如 "dnssb"）
	geoFallback    bool   = true // DoT 失败时是否回退系统 DNS
	geoMu          sync.RWMutex
	geoApplyMu     sync.Mutex
	geoScopeMu     sync.Mutex
	geoScopePolicy GeoDNSPolicy
	geoScopePrev   GeoDNSPolicy
	geoScopeDepth  int

	// geoResolverOverride 允许测试注入自定义 resolver（仅测试用）。
	// 非 nil 时 LookupHostForGeo 的 DoT 阶段使用该 resolver 替代 ResolverForDot 的结果。
	geoResolverOverride *net.Resolver
)

// GeoDNSPolicy is an immutable, comparable Geo DNS configuration.
// Use NewGeoDNSPolicy so resolver names are normalized before comparison or caching.
type GeoDNSPolicy struct {
	resolver string
	fallback bool
}

// NewGeoDNSPolicy creates a normalized Geo DNS policy.
func NewGeoDNSPolicy(resolver string, fallback bool) GeoDNSPolicy {
	return GeoDNSPolicy{
		resolver: normalizeGeoDNSResolver(resolver),
		fallback: fallback,
	}
}

// Resolver returns the normalized DoT resolver name.
func (p GeoDNSPolicy) Resolver() string {
	return p.resolver
}

// Fallback reports whether a failed DoT lookup falls back to the system resolver.
func (p GeoDNSPolicy) Fallback() bool {
	return p.fallback
}

func setGeoResolverOverride(resolver *net.Resolver) {
	geoMu.Lock()
	defer geoMu.Unlock()
	geoResolverOverride = resolver
}

func getGeoResolverOverride() *net.Resolver {
	geoMu.RLock()
	defer geoMu.RUnlock()
	return geoResolverOverride
}

// SetGeoDNSResolver 设置 Geo 解析使用的 DoT 服务器名称。
// 空字符串表示仅使用系统 DNS。
func SetGeoDNSResolver(dotServer string) {
	geoMu.Lock()
	defer geoMu.Unlock()
	geoDotServer = normalizeGeoDNSResolver(dotServer)
}

// CurrentGeoDNSResolver 返回当前生效的 Geo DNS resolver 名称（已规范化）。
func CurrentGeoDNSResolver() string {
	return CurrentGeoDNSPolicy().Resolver()
}

func normalizeGeoDNSResolver(dotServer string) string {
	return strings.ToLower(strings.TrimSpace(dotServer))
}

// SetGeoDNSFallback 设置 DoT 失败后是否回退系统 DNS，默认 true。
func SetGeoDNSFallback(enabled bool) {
	geoMu.Lock()
	defer geoMu.Unlock()
	geoFallback = enabled
}

// CurrentGeoDNSPolicy returns one consistent snapshot of the active Geo DNS policy.
func CurrentGeoDNSPolicy() GeoDNSPolicy {
	geoMu.RLock()
	defer geoMu.RUnlock()
	return NewGeoDNSPolicy(geoDotServer, geoFallback)
}

func setGeoDNSPolicy(policy GeoDNSPolicy) {
	policy = NewGeoDNSPolicy(policy.Resolver(), policy.Fallback())
	geoMu.Lock()
	geoDotServer = policy.Resolver()
	geoFallback = policy.Fallback()
	geoMu.Unlock()
}

// WithGeoDNSResolver 在 callback 生命周期内临时切换 Geo DNS resolver。
// 该辅助会串行化不同 resolver 的切换与恢复，并允许相同 resolver 作用域安全嵌套。
func WithGeoDNSResolver[T any](dotServer string, callback func() (T, error)) (T, error) {
	if callback == nil {
		var zero T
		return zero, nil
	}
	dotServer = normalizeGeoDNSResolver(dotServer)

	geoApplyMu.Lock()
	if geoScopeDepth > 0 && geoScopePolicy.Resolver() == dotServer {
		geoScopeDepth++
		geoApplyMu.Unlock()
		defer releaseGeoDNSResolverScope()
		return callback()
	}
	geoApplyMu.Unlock()

	geoScopeMu.Lock()
	previous := CurrentGeoDNSPolicy()
	policy := NewGeoDNSPolicy(dotServer, previous.Fallback())
	setGeoDNSPolicy(policy)
	geoApplyMu.Lock()
	geoScopePolicy = policy
	geoScopePrev = previous
	geoScopeDepth = 1
	geoApplyMu.Unlock()
	defer releaseGeoDNSResolverScope()

	return callback()
}

func releaseGeoDNSResolverScope() {
	geoApplyMu.Lock()
	if geoScopeDepth <= 0 {
		geoApplyMu.Unlock()
		return
	}
	geoScopeDepth--
	if geoScopeDepth > 0 {
		geoApplyMu.Unlock()
		return
	}

	previous := geoScopePrev
	geoScopePolicy = GeoDNSPolicy{}
	geoScopePrev = GeoDNSPolicy{}
	geoApplyMu.Unlock()

	setGeoDNSPolicy(previous)
	geoScopeMu.Unlock()
}

// getGeoDNSConfig 返回当前快照；并发安全。
func getGeoDNSConfig() (dotServer string, fallback bool) {
	policy := CurrentGeoDNSPolicy()
	return policy.Resolver(), policy.Fallback()
}

// ResolverForDot 根据 dotServer 名字返回对应的 *net.Resolver。
// 空 / 未知名字返回 nil（表示"使用系统默认"）。
func ResolverForDot(dotServer string) *net.Resolver {
	switch dotServer {
	case "dnssb":
		return DNSSB()
	case "aliyun":
		return Aliyun()
	case "dnspod":
		return Dnspod()
	case "google":
		return Google()
	case "cloudflare":
		return Cloudflare()
	default:
		return nil
	}
}

// LookupHostForGeo 执行"Geo 专用"DNS 查询。
//
//  1. 如果 host 是 IP 字面量，直接返回，不做 DNS 查询。
//  2. 若配置了 DoT，优先用 DoT 解析。
//  3. DoT 失败且 fallback=true 时，回退系统 DNS。
//  4. 全部失败才返回 error。
func LookupHostForGeo(ctx context.Context, host string) ([]net.IP, error) {
	return LookupHostForGeoWithPolicy(ctx, host, CurrentGeoDNSPolicy())
}

// LookupHostForGeoWithPolicy resolves host with one immutable Geo DNS policy.
func LookupHostForGeoWithPolicy(ctx context.Context, host string, policy GeoDNSPolicy) ([]net.IP, error) {
	// ── 1. IP 字面量短路 ──
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	policy = NewGeoDNSPolicy(policy.Resolver(), policy.Fallback())

	// ── 2. DoT 解析 ──
	r := ResolverForDot(policy.Resolver())
	if override := getGeoResolverOverride(); override != nil {
		r = override
	}
	if r != nil {
		ips, err := resolveHost(ctx, r, host)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		// DoT 失败，决定是否 fallback
		if !policy.Fallback() {
			if err != nil {
				return nil, err
			}
			return nil, &net.DNSError{
				Err:  "no addresses found via DoT",
				Name: host,
			}
		}
		// 继续到 fallback
	}

	// ── 3. Fallback: 系统 DNS ──
	return resolveHost(ctx, net.DefaultResolver, host)
}

// resolveHost 用给定的 resolver 解析 host，返回 []net.IP。
func resolveHost(ctx context.Context, r *net.Resolver, host string) ([]net.IP, error) {
	// 使用较短的独立超时，避免阻塞调用方
	child, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := r.LookupHost(child, host)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, &net.DNSError{
			Err:  "no addresses found",
			Name: host,
		}
	}
	return ips, nil
}
