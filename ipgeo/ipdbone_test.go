package ipgeo

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type ipdbOneRoundTripFunc func(*http.Request) (*http.Response, error)

func (f ipdbOneRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type ipdbOneTokenResult struct {
	token string
	err   error
}

func newIPDBOneTestClient(timeout time.Duration, transport http.RoundTripper) *IPDBOneClient {
	client := NewIPDBOneClient()
	client.config = &IPDBOneConfig{
		BaseURL: "https://ipdb-one.test",
		ApiID:   "api-id",
		ApiKey:  "api-key",
	}
	client.tokenHTTPClient = &http.Client{Transport: transport}
	client.httpClient = &http.Client{Transport: transport, Timeout: timeout}
	return client
}

func ipdbOneJSONResponse(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func startIPDBOneTokenBatch(client *IPDBOneClient, count int) <-chan []ipdbOneTokenResult {
	done := make(chan []ipdbOneTokenResult, 1)
	start := make(chan struct{})
	results := make([]ipdbOneTokenResult, count)
	var workers sync.WaitGroup
	workers.Add(count)
	for i := range count {
		go func() {
			defer workers.Done()
			<-start
			results[i].token, results[i].err = client.ensureToken(context.Background())
		}()
	}
	close(start)
	go func() {
		workers.Wait()
		done <- results
	}()
	return done
}

func waitIPDBOneTokenBatch(t *testing.T, done <-chan []ipdbOneTokenResult) []ipdbOneTokenResult {
	t.Helper()
	select {
	case results := <-done:
		return results
	case <-time.After(2 * time.Second):
		t.Fatal("token batch did not complete")
		return nil
	}
}

func TestIPDBOneTokenFetchSingleflight(t *testing.T) {
	for _, tc := range []struct {
		name        string
		expiredSeed bool
	}{
		{name: "first fetch"},
		{name: "expired refresh", expiredSeed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var authCalls atomic.Int32
			authStarted := make(chan struct{}, 1)
			releaseAuth := make(chan struct{})
			client := newIPDBOneTestClient(time.Second, ipdbOneRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				authCalls.Add(1)
				select {
				case authStarted <- struct{}{}:
				default:
				}
				<-releaseAuth
				return ipdbOneJSONResponse(req, `{"code":200,"data":{"token":"shared-token"}}`), nil
			}))
			if tc.expiredSeed {
				client.tokenCache.SetToken("expired-token", -time.Second)
			}

			done := startIPDBOneTokenBatch(client, 32)
			select {
			case <-authStarted:
			case <-time.After(time.Second):
				t.Fatal("authentication request did not start")
			}
			time.Sleep(20 * time.Millisecond)
			close(releaseAuth)

			for i, result := range waitIPDBOneTokenBatch(t, done) {
				if result.err != nil || result.token != "shared-token" {
					t.Fatalf("result[%d] = (%q, %v), want shared-token, nil", i, result.token, result.err)
				}
			}
			if got := authCalls.Load(); got != 1 {
				t.Fatalf("authentication requests = %d, want 1", got)
			}
		})
	}
}

func TestIPDBOneTokenFetchErrorIsSharedAndRetryable(t *testing.T) {
	var (
		authCalls atomic.Int32
		retryOK   atomic.Bool
	)
	authStarted := make(chan struct{}, 1)
	releaseAuth := make(chan struct{})
	client := newIPDBOneTestClient(time.Second, ipdbOneRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		authCalls.Add(1)
		if retryOK.Load() {
			return ipdbOneJSONResponse(req, `{"code":200,"data":{"token":"retry-token"}}`), nil
		}
		select {
		case authStarted <- struct{}{}:
		default:
		}
		<-releaseAuth
		return ipdbOneJSONResponse(req, `{"code":500,"message":"temporary auth failure"}`), nil
	}))

	done := startIPDBOneTokenBatch(client, 24)
	select {
	case <-authStarted:
	case <-time.After(time.Second):
		t.Fatal("authentication request did not start")
	}
	time.Sleep(20 * time.Millisecond)
	close(releaseAuth)

	results := waitIPDBOneTokenBatch(t, done)
	firstErr := results[0].err
	if firstErr == nil || firstErr.Error() != "failed to authenticate: temporary auth failure" {
		t.Fatalf("first error = %v", firstErr)
	}
	for i, result := range results {
		if result.token != "" || result.err != firstErr {
			t.Fatalf("result[%d] = (%q, %v), want the original shared error %v", i, result.token, result.err, firstErr)
		}
	}
	if got := authCalls.Load(); got != 1 {
		t.Fatalf("authentication requests after failed batch = %d, want 1", got)
	}
	if token := client.tokenCache.GetToken(); token != "" {
		t.Fatalf("cached token after failure = %q, want empty", token)
	}

	retryOK.Store(true)
	token, err := client.ensureToken(context.Background())
	if err != nil || token != "retry-token" {
		t.Fatalf("retry = (%q, %v), want retry-token, nil", token, err)
	}
	if got := authCalls.Load(); got != 2 {
		t.Fatalf("authentication requests after retry = %d, want 2", got)
	}
}

func TestIPDBOneTokenFetchRejectsEmptyToken(t *testing.T) {
	client := newIPDBOneTestClient(time.Second, ipdbOneRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return ipdbOneJSONResponse(req, `{"code":200,"data":{"token":""}}`), nil
	}))

	token, err := client.ensureToken(context.Background())
	if token != "" || err == nil || err.Error() != "authentication failed: empty token received" {
		t.Fatalf("ensureToken() = (%q, %v), want empty token error", token, err)
	}
	if cached := client.tokenCache.GetToken(); cached != "" {
		t.Fatalf("cached token = %q, want empty", cached)
	}
}

func TestIPDBOneTokenCacheExpiration(t *testing.T) {
	cache := &IPDBOneTokenCache{}
	cache.SetToken("valid-token", time.Second)
	if got := cache.GetToken(); got != "valid-token" {
		t.Fatalf("valid cached token = %q, want valid-token", got)
	}

	cache.SetToken("expired-token", 0)
	if got := cache.GetToken(); got != "" {
		t.Fatalf("zero-TTL cached token = %q, want empty", got)
	}
}

func TestIPDBOneTokenFlightRechecksCache(t *testing.T) {
	var requests atomic.Int32
	client := newIPDBOneTestClient(time.Second, ipdbOneRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected request")
	}))
	client.tokenCache.SetToken("cached-by-peer", time.Second)

	token, err := client.fetchTokenIfNeeded(context.Background())
	if err != nil || token != "cached-by-peer" {
		t.Fatalf("fetchTokenIfNeeded() = (%q, %v), want cached-by-peer, nil", token, err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0", got)
	}
}

func TestIPDBOneTokenRequiresCredentials(t *testing.T) {
	var requests atomic.Int32
	client := newIPDBOneTestClient(time.Second, ipdbOneRoundTripFunc(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected request")
	}))
	client.config.ApiID = ""

	token, err := client.ensureToken(context.Background())
	if token != "" || err == nil || err.Error() != "api id or api key is not set" {
		t.Fatalf("ensureToken() = (%q, %v), want missing credentials error", token, err)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("requests = %d, want 0", got)
	}
}

func TestIPDBOneTokenWaiterCancellationDoesNotCancelSharedFetch(t *testing.T) {
	var authCalls atomic.Int32
	authStarted := make(chan struct{}, 1)
	releaseAuth := make(chan struct{})
	client := newIPDBOneTestClient(time.Second, ipdbOneRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		authCalls.Add(1)
		select {
		case authStarted <- struct{}{}:
		default:
		}
		select {
		case <-releaseAuth:
			return ipdbOneJSONResponse(req, `{"code":200,"data":{"token":"shared-token"}}`), nil
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}))

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan ipdbOneTokenResult, 1)
	go func() {
		token, err := client.ensureToken(leaderCtx)
		leaderDone <- ipdbOneTokenResult{token: token, err: err}
	}()
	select {
	case <-authStarted:
	case <-time.After(time.Second):
		t.Fatal("authentication request did not start")
	}

	waiterDone := make(chan ipdbOneTokenResult, 1)
	go func() {
		token, err := client.ensureToken(context.Background())
		waiterDone <- ipdbOneTokenResult{token: token, err: err}
	}()
	time.Sleep(10 * time.Millisecond)
	cancelLeader()

	select {
	case result := <-leaderDone:
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("canceled leader error = %v, want context.Canceled", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled leader did not return")
	}

	close(releaseAuth)
	select {
	case result := <-waiterDone:
		if result.err != nil || result.token != "shared-token" {
			t.Fatalf("waiter = (%q, %v), want shared-token, nil", result.token, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter did not receive shared token")
	}
	if got := authCalls.Load(); got != 1 {
		t.Fatalf("authentication requests = %d, want 1", got)
	}
}

func TestIPDBOneTokenFlightDoesNotInheritShortWaiterTimeout(t *testing.T) {
	var authCalls atomic.Int32
	authStarted := make(chan struct{}, 1)
	client := newIPDBOneTestClient(time.Second, ipdbOneRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		authCalls.Add(1)
		select {
		case authStarted <- struct{}{}:
		default:
		}
		timer := time.NewTimer(150 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			return ipdbOneJSONResponse(req, `{"code":200,"data":{"token":"shared-token"}}`), nil
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}))
	shortClient := client.cloneWithTimeout(50 * time.Millisecond)
	longClient := client.cloneWithTimeout(time.Second)

	shortCtx, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	shortDone := make(chan ipdbOneTokenResult, 1)
	go func() {
		token, err := shortClient.ensureToken(shortCtx)
		shortDone <- ipdbOneTokenResult{token: token, err: err}
	}()
	select {
	case <-authStarted:
	case <-time.After(time.Second):
		t.Fatal("authentication request did not start")
	}

	longCtx, cancelLong := context.WithTimeout(context.Background(), time.Second)
	defer cancelLong()
	longDone := make(chan ipdbOneTokenResult, 1)
	go func() {
		token, err := longClient.ensureToken(longCtx)
		longDone <- ipdbOneTokenResult{token: token, err: err}
	}()

	select {
	case result := <-shortDone:
		if !errors.Is(result.err, context.DeadlineExceeded) {
			t.Fatalf("short waiter error = %v, want context deadline exceeded", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("short waiter did not honor its timeout")
	}
	select {
	case result := <-longDone:
		if result.err != nil || result.token != "shared-token" {
			t.Fatalf("long waiter = (%q, %v), want shared-token, nil", result.token, result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("long waiter inherited the short timeout")
	}
	if got := authCalls.Load(); got != 2 {
		t.Fatalf("authentication requests = %d, want 2 after the short flight expires and the long waiter retries", got)
	}
}

func TestIPDBOneCloneSharesTokenState(t *testing.T) {
	client := NewIPDBOneClient()
	clone := client.cloneWithTimeout(5 * time.Second)
	if clone.tokenCache != client.tokenCache {
		t.Fatal("clone does not share token cache")
	}
	if clone.tokenGroup != client.tokenGroup {
		t.Fatal("clone does not share token singleflight group")
	}
	if clone.tokenHTTPClient != client.tokenHTTPClient {
		t.Fatal("clone does not share the stable token HTTP client")
	}
	client.tokenCache.SetToken("cached-token", 30*time.Second)
	if got := clone.tokenCache.GetToken(); got != "cached-token" {
		t.Fatalf("clone cached token = %q, want cached-token", got)
	}
}

func TestIPDBOneLookupUsesTokenAndTotalTimeoutContext(t *testing.T) {
	const timeout = 2 * time.Second
	var (
		queryAuthorization string
		authDeadline       time.Time
		queryDeadline      time.Time
	)
	client := newIPDBOneTestClient(timeout, ipdbOneRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/auth/requestToken/query":
			authDeadline, _ = req.Context().Deadline()
			return ipdbOneJSONResponse(req, `{"code":200,"data":{"token":"request-token"}}`), nil
		case "/query/1.1.1.1":
			queryAuthorization = req.Header.Get("Authorization")
			queryDeadline, _ = req.Context().Deadline()
			return ipdbOneJSONResponse(req, `{"code":200,"data":{"geo":{"country":"US"}}}`), nil
		default:
			return nil, errors.New("unexpected IPDB.One request path: " + req.URL.Path)
		}
	}))

	result, err := client.LookupIP("1.1.1.1", "en")
	if err != nil {
		t.Fatalf("LookupIP() error = %v", err)
	}
	if result.Country != "US" {
		t.Fatalf("LookupIP() country = %q, want US", result.Country)
	}
	if queryAuthorization != "Bearer request-token" {
		t.Fatalf("Authorization = %q, want Bearer request-token", queryAuthorization)
	}
	if authDeadline.IsZero() || queryDeadline.IsZero() {
		t.Fatalf("request deadlines = (%v, %v), want both set", authDeadline, queryDeadline)
	}
	if !authDeadline.Equal(queryDeadline) {
		t.Fatalf("auth deadline = %v, query deadline = %v; want one total budget", authDeadline, queryDeadline)
	}
}
