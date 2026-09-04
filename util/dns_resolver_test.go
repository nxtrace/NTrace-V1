package util

import (
	"bytes"
	"context"
	"net"
	"runtime"
	"testing"
	"time"
)

type geoResolverScopeObservation struct {
	resolver string
	fallback bool
}

// ── ResolverForDot 映射 ─────────────────────────────

func TestResolverMapping(t *testing.T) {
	known := []string{"dnssb", "aliyun", "dnspod", "google", "cloudflare"}
	for _, name := range known {
		r := ResolverForDot(name)
		if r == nil {
			t.Fatalf("ResolverForDot(%q) returned nil, want non-nil", name)
		}
		// 确认是自定义 dialer（PreferGo = true 且有 Dial）
		if !r.PreferGo {
			t.Errorf("ResolverForDot(%q).PreferGo = false, want true", name)
		}
	}
	// 空字符串 / 未知值返回 nil（表示系统默认）
	for _, name := range []string{"", "unknown", "xxx"} {
		if r := ResolverForDot(name); r != nil {
			t.Errorf("ResolverForDot(%q) = %v, want nil", name, r)
		}
	}
}

func TestGeoDNSPolicyNormalizesAndComparesByResolverAndFallback(t *testing.T) {
	first := NewGeoDNSPolicy(" CloudFlare ", true)
	second := NewGeoDNSPolicy("cloudflare", true)
	withoutFallback := NewGeoDNSPolicy("cloudflare", false)
	if first != second {
		t.Fatalf("normalized policies differ: %#v != %#v", first, second)
	}
	if first == withoutFallback {
		t.Fatalf("policies with different fallback behavior compare equal: %#v", first)
	}
	if first.Resolver() != "cloudflare" || !first.Fallback() {
		t.Fatalf("policy = (%q, %t), want (%q, %t)", first.Resolver(), first.Fallback(), "cloudflare", true)
	}
}

// ── IP 字面量短路 ────────────────────────────────────

func TestLookupHostForGeo_IPLiteral(t *testing.T) {
	// 无论 DoT 配置为何，IP 字面量应直接返回，不触发 DNS 查询。
	SetGeoDNSResolver("dnssb")
	defer SetGeoDNSResolver("")

	cases := []string{"1.1.1.1", "::1", "2001:db8::1", "192.168.0.1"}
	for _, addr := range cases {
		ips, err := LookupHostForGeo(context.Background(), addr)
		if err != nil {
			t.Errorf("LookupHostForGeo(%q) err = %v, want nil", addr, err)
			continue
		}
		if len(ips) != 1 || ips[0].String() != net.ParseIP(addr).String() {
			t.Errorf("LookupHostForGeo(%q) = %v, want [%s]", addr, ips, addr)
		}
	}
}

// ── DoT 成功时不走 fallback ──────────────────────────

func TestLookupHostForGeo_DoTSuccess(t *testing.T) {
	// 使用 Cloudflare DoT 解析一个可靠域名
	SetGeoDNSResolver("cloudflare")
	SetGeoDNSFallback(true)
	defer func() {
		SetGeoDNSResolver("")
		SetGeoDNSFallback(true)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := LookupHostForGeo(ctx, "one.one.one.one")
	if err != nil {
		t.Skipf("DoT lookup failed (network issue?): %v", err)
	}
	if len(ips) == 0 {
		t.Error("expected at least 1 IP, got 0")
	}
}

// ── 未配置 DoT 时直接走系统 DNS ──────────────────────

func TestLookupHostForGeo_NoDotFallsToSystem(t *testing.T) {
	// dotServer 为空 → ResolverForDot 返回 nil → 直接走系统 DNS。
	SetGeoDNSResolver("")
	SetGeoDNSFallback(true)
	defer func() {
		SetGeoDNSResolver("")
		SetGeoDNSFallback(true)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := LookupHostForGeo(ctx, "one.one.one.one")
	if err != nil {
		t.Skipf("System DNS lookup failed (network issue?): %v", err)
	}
	if len(ips) == 0 {
		t.Error("expected at least 1 IP, got 0")
	}
}

// ── DoT 失败后回退系统 DNS ───────────────────────────

func TestLookupHostForGeo_DoTFailFallback(t *testing.T) {
	// 注入一个必定失败的 resolver（连接不可达地址），
	// 验证 fallback=true 时能回退到系统 DNS 成功解析。
	badResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// 拨向 RFC 5737 文档专用地址，必定失败
			return net.DialTimeout("tcp", "192.0.2.1:853", 200*time.Millisecond)
		},
	}
	SetGeoDNSResolver("cloudflare") // 需要非空，ResolverForDot 会被 override 覆盖
	SetGeoDNSFallback(true)
	setGeoResolverOverride(badResolver)
	defer func() {
		setGeoResolverOverride(nil)
		SetGeoDNSResolver("")
		SetGeoDNSFallback(true)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ips, err := LookupHostForGeo(ctx, "one.one.one.one")
	if err != nil {
		t.Skipf("System DNS fallback also failed (network issue?): %v", err)
	}
	if len(ips) == 0 {
		t.Error("expected at least 1 IP from system DNS fallback, got 0")
	}
}

// ── DoT 失败且 fallback=false 时返回错误 ─────────────

func TestLookupHostForGeo_DoTFailNoFallback(t *testing.T) {
	badResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.DialTimeout("tcp", "192.0.2.1:853", 200*time.Millisecond)
		},
	}
	SetGeoDNSResolver("cloudflare")
	SetGeoDNSFallback(false)
	setGeoResolverOverride(badResolver)
	defer func() {
		setGeoResolverOverride(nil)
		SetGeoDNSResolver("")
		SetGeoDNSFallback(true)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := LookupHostForGeo(ctx, "one.one.one.one")
	if err == nil {
		t.Error("expected error when DoT fails and fallback=false, got nil")
	}
}

// ── SetGeoDNSResolver / SetGeoDNSFallback 并发安全 ──

func TestGeoDNSConfig_ConcurrentAccess(t *testing.T) {
	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			SetGeoDNSResolver("google")
			SetGeoDNSFallback(false)
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		_, _ = getGeoDNSConfig()
	}
	<-done
	// 无 data race = 通过
}

func TestWithGeoDNSResolver_RestoresPreviousConfig(t *testing.T) {
	SetGeoDNSResolver("google")
	SetGeoDNSFallback(false)
	defer func() {
		SetGeoDNSResolver("")
		SetGeoDNSFallback(true)
	}()

	seenDot := ""
	seenFallback := true
	got, err := WithGeoDNSResolver("cloudflare", func() (string, error) {
		seenDot, seenFallback = getGeoDNSConfig()
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("WithGeoDNSResolver returned error: %v", err)
	}
	if got != "ok" {
		t.Fatalf("WithGeoDNSResolver result = %q, want ok", got)
	}
	if seenDot != "cloudflare" {
		t.Fatalf("callback saw dot resolver %q, want cloudflare", seenDot)
	}
	if seenFallback {
		t.Fatalf("callback saw fallback=true, want inherited false")
	}

	dot, fallback := getGeoDNSConfig()
	if dot != "google" || fallback {
		t.Fatalf("resolver restored to (%q, %t), want (%q, %t)", dot, fallback, "google", false)
	}
}

func TestSetGeoDNSResolver_NormalizesName(t *testing.T) {
	SetGeoDNSResolver(" Google ")
	defer SetGeoDNSResolver("")

	if got := CurrentGeoDNSResolver(); got != "google" {
		t.Fatalf("CurrentGeoDNSResolver() = %q, want google", got)
	}
}

func TestWithGeoDNSResolver_AllowsNestedSameResolver(t *testing.T) {
	SetGeoDNSResolver("google")
	SetGeoDNSFallback(false)
	defer func() {
		SetGeoDNSResolver("")
		SetGeoDNSFallback(true)
	}()

	done := make(chan struct{})
	var (
		got            string
		err            error
		outerDot       string
		outerFallback  bool
		nestedDot      string
		nestedFallback bool
	)

	go func() {
		defer close(done)
		got, err = WithGeoDNSResolver(" CloudFlare ", func() (string, error) {
			outerDot, outerFallback = getGeoDNSConfig()
			return WithGeoDNSResolver("cloudflare", func() (string, error) {
				nestedDot, nestedFallback = getGeoDNSConfig()
				return "nested", nil
			})
		})
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("nested WithGeoDNSResolver call deadlocked")
	}

	if err != nil {
		t.Fatalf("nested WithGeoDNSResolver returned error: %v", err)
	}
	if got != "nested" {
		t.Fatalf("nested WithGeoDNSResolver result = %q, want nested", got)
	}
	if outerDot != "cloudflare" || outerFallback {
		t.Fatalf("outer callback saw (%q, %t), want (%q, %t)", outerDot, outerFallback, "cloudflare", false)
	}
	if nestedDot != "cloudflare" || nestedFallback {
		t.Fatalf("nested callback saw (%q, %t), want (%q, %t)", nestedDot, nestedFallback, "cloudflare", false)
	}

	dot, fallback := getGeoDNSConfig()
	if dot != "google" || fallback {
		t.Fatalf("resolver restored to (%q, %t), want (%q, %t)", dot, fallback, "google", false)
	}
}

func TestWithGeoDNSResolver_EmptyScopeIsolatedFromConcurrentDoT(t *testing.T) {
	SetGeoDNSResolver("google")
	SetGeoDNSFallback(false)
	defer func() {
		SetGeoDNSResolver("")
		SetGeoDNSFallback(true)
	}()

	dotEntered := make(chan struct{})
	releaseDot := make(chan struct{})
	dotDone := make(chan struct{})
	go func() {
		defer close(dotDone)
		_, _ = WithGeoDNSResolver("cloudflare", func() (struct{}, error) {
			close(dotEntered)
			<-releaseDot
			return struct{}{}, nil
		})
	}()
	<-dotEntered

	emptyStarted := make(chan struct{})
	emptyDone := make(chan struct{})
	emptyPolicy := make(chan geoResolverScopeObservation, 1)
	go observeEmptyGeoResolverScope(emptyStarted, emptyDone, emptyPolicy)
	<-emptyStarted

	blocked, completed, got := waitForGeoResolverScopeBlock(t, emptyPolicy)
	if completed {
		close(releaseDot)
		<-dotDone
		<-emptyDone
		t.Fatalf("empty resolver scope entered active DoT scope and saw (%q, %t)", got.resolver, got.fallback)
	}
	if !blocked {
		close(releaseDot)
		<-dotDone
		<-emptyDone
		t.Fatal("empty resolver scope never reached the active scope lock")
	}

	close(releaseDot)
	<-dotDone
	select {
	case got := <-emptyPolicy:
		if got.resolver != "" || got.fallback {
			t.Fatalf("empty scope saw (%q, %t), want (%q, %t)", got.resolver, got.fallback, "", false)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("empty resolver scope did not resume after DoT scope exited")
	}
	<-emptyDone

	resolver, fallback := getGeoDNSConfig()
	if resolver != "google" || fallback {
		t.Fatalf("resolver restored to (%q, %t), want (%q, %t)", resolver, fallback, "google", false)
	}
}

//go:noinline
func observeEmptyGeoResolverScope(started chan<- struct{}, done chan<- struct{}, result chan<- geoResolverScopeObservation) {
	defer close(done)
	close(started)
	_, _ = WithGeoDNSResolver("", func() (struct{}, error) {
		resolver, fallback := getGeoDNSConfig()
		result <- geoResolverScopeObservation{resolver: resolver, fallback: fallback}
		return struct{}{}, nil
	})
}

func waitForGeoResolverScopeBlock(t *testing.T, result <-chan geoResolverScopeObservation) (blocked bool, completed bool, got geoResolverScopeObservation) {
	t.Helper()
	const maxStackDumpSize = 16 << 20
	deadline := time.Now().Add(2 * time.Second)
	stack := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		select {
		case got = <-result:
			return false, true, got
		default:
		}
		n := runtime.Stack(stack, true)
		for n == len(stack) {
			if len(stack) >= maxStackDumpSize {
				t.Errorf("goroutine stack dump exceeded %d bytes", maxStackDumpSize)
				return false, false, got
			}
			stack = make([]byte, min(len(stack)*2, maxStackDumpSize))
			n = runtime.Stack(stack, true)
		}
		for _, goroutine := range bytes.Split(stack[:n], []byte("\n\n")) {
			if bytes.Contains(goroutine, []byte("observeEmptyGeoResolverScope")) &&
				bytes.Contains(goroutine, []byte("[sync.Mutex.Lock")) {
				return true, false, got
			}
		}
		runtime.Gosched()
	}
	return false, false, got
}

func TestWithGeoDNSResolver_AllowsNestedEmptyResolver(t *testing.T) {
	SetGeoDNSResolver("google")
	SetGeoDNSFallback(false)
	defer func() {
		SetGeoDNSResolver("")
		SetGeoDNSFallback(true)
	}()

	done := make(chan struct{})
	var (
		outerResolver string
		innerResolver string
	)
	go func() {
		defer close(done)
		_, _ = WithGeoDNSResolver("", func() (struct{}, error) {
			outerResolver, _ = getGeoDNSConfig()
			return WithGeoDNSResolver("", func() (struct{}, error) {
				innerResolver, _ = getGeoDNSConfig()
				return struct{}{}, nil
			})
		})
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("nested empty resolver scope deadlocked")
	}
	if outerResolver != "" || innerResolver != "" {
		t.Fatalf("nested empty scopes saw (%q, %q), want empty resolvers", outerResolver, innerResolver)
	}
	resolver, fallback := getGeoDNSConfig()
	if resolver != "google" || fallback {
		t.Fatalf("resolver restored to (%q, %t), want (%q, %t)", resolver, fallback, "google", false)
	}
}
