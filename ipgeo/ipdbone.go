package ipgeo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/sync/singleflight"

	"github.com/nxtrace/NTrace-core/config"
	"github.com/nxtrace/NTrace-core/util"
)

const (
	ipdbOneDefaultTimeout = 3 * time.Second
	ipdbOneTokenTTL       = 30 * time.Second
)

// LangMap shows language mapping for IPDB.One API
var LangMap = map[string]string{
	"en": "en",
	"cn": "zh",
}

// IPDBOneConfig holds the configuration for IPDB.One service
type IPDBOneConfig struct {
	BaseURL string
	ApiID   string
	ApiKey  string
}

// GetDefaultConfig returns the default configuration with fallback values
func GetDefaultConfig() *IPDBOneConfig {
	return &IPDBOneConfig{
		BaseURL: util.GetEnvDefault("IPDBONE_BASE_URL", "https://api.ipdb.one"),
		ApiID:   util.GetSecretEnvDefault("IPDBONE_API_ID", ""),
		ApiKey:  util.GetSecretEnvDefault("IPDBONE_API_KEY", ""),
	}
}

// IPDBOneTokenCache manages the caching of auth tokens
type IPDBOneTokenCache struct {
	token     string
	expiresAt time.Time
	mutex     sync.RWMutex
}

// GetToken retrieves cached token if valid, otherwise returns empty string
func (c *IPDBOneTokenCache) GetToken() string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	if c.token == "" || !time.Now().Before(c.expiresAt) {
		return ""
	}
	return c.token
}

// SetToken updates the token with its expiration time
func (c *IPDBOneTokenCache) SetToken(token string, expiresIn time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.token = token
	c.expiresAt = time.Now().Add(expiresIn)
}

// IPDBOneClient handles communication with IPDB.One API
type IPDBOneClient struct {
	config          *IPDBOneConfig
	tokenCache      *IPDBOneTokenCache
	tokenGroup      *singleflight.Group
	geoDNSPolicy    util.GeoDNSPolicy
	tokenHTTPClient *http.Client
	httpClient      *http.Client
}

type ipdbOneTokenFlightDeadlineError struct {
	err      error
	deadline time.Time
}

func (e *ipdbOneTokenFlightDeadlineError) Error() string {
	return e.err.Error()
}

func (e *ipdbOneTokenFlightDeadlineError) Unwrap() error {
	return e.err
}

// NewIPDBOneClient creates a new client for IPDB.One with default configuration
func NewIPDBOneClient() *IPDBOneClient {
	policy := util.CurrentGeoDNSPolicy()
	httpClient := util.NewSharedGeoHTTPClientWithPolicy(ipdbOneDefaultTimeout, policy)
	return &IPDBOneClient{
		config:          GetDefaultConfig(),
		tokenCache:      &IPDBOneTokenCache{},
		tokenGroup:      &singleflight.Group{},
		geoDNSPolicy:    policy,
		tokenHTTPClient: util.NewSharedGeoHTTPClientWithPolicy(0, policy),
		httpClient:      httpClient,
	}
}

func (c *IPDBOneClient) cloneWithTimeout(timeout time.Duration) *IPDBOneClient {
	if c == nil {
		return c
	}
	policy := util.CurrentGeoDNSPolicy()
	if timeout <= 0 {
		timeout = c.httpClient.Timeout
	}
	tokenHTTPClient := c.tokenHTTPClient
	if policy != c.geoDNSPolicy {
		tokenHTTPClient = util.NewSharedGeoHTTPClientWithPolicy(0, policy)
	}
	return &IPDBOneClient{
		config:          c.config,
		tokenCache:      c.tokenCache,
		tokenGroup:      c.tokenGroup,
		geoDNSPolicy:    policy,
		tokenHTTPClient: tokenHTTPClient,
		httpClient:      util.NewSharedGeoHTTPClientWithPolicy(timeout, policy),
	}
}

// fetchToken requests a new authentication token from the API
func (c *IPDBOneClient) fetchToken(ctx context.Context) (string, error) {
	authURL := c.config.BaseURL + "/auth/requestToken/query"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authURL, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NextTrace/"+config.Version)
	req.Header.Set("x-api-id", c.config.ApiID)
	req.Header.Set("x-api-key", c.config.ApiKey)

	resp, err := c.tokenHTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	statusCode := gjson.Get(string(body), "code").Int()
	statusMessage := gjson.Get(string(body), "message").String()

	if statusCode != 200 {
		return "", errors.New("failed to authenticate: " + statusMessage)
	}

	token := gjson.Get(string(body), "data.token").String()
	if token == "" {
		return "", errors.New("authentication failed: empty token received")
	}

	// Cache token with a 30-second expiration
	c.tokenCache.SetToken(token, ipdbOneTokenTTL)
	return token, nil
}

// ensureToken makes sure a valid token is available, fetching a new one if needed
func (c *IPDBOneClient) ensureToken(ctx context.Context) (string, error) {
	// Ensure API credentials are set
	if c.config.ApiID == "" || c.config.ApiKey == "" {
		return "", errors.New("api id or api key is not set")
	}

	if token := c.tokenCache.GetToken(); token != "" {
		return token, nil
	}

	for {
		resultCh := c.tokenGroup.DoChan("token", func() (any, error) {
			fetchCtx, cancel := c.tokenFlightContext(ctx)
			defer cancel()
			token, err := c.fetchTokenIfNeeded(fetchCtx)
			if err != nil && errors.Is(fetchCtx.Err(), context.DeadlineExceeded) {
				deadline, _ := fetchCtx.Deadline()
				return "", &ipdbOneTokenFlightDeadlineError{err: err, deadline: deadline}
			}
			return token, err
		})

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case result := <-resultCh:
			if result.Err != nil {
				if c.shouldRetryTokenFlight(ctx, result.Err) {
					continue
				}
				return "", result.Err
			}
			return result.Val.(string), nil
		}
	}
}

func (c *IPDBOneClient) fetchTokenIfNeeded(ctx context.Context) (string, error) {
	if token := c.tokenCache.GetToken(); token != "" {
		return token, nil
	}
	return c.fetchToken(ctx)
}

func (c *IPDBOneClient) tokenFlightContext(waiter context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := waiter.Deadline(); ok {
		return context.WithDeadline(context.WithoutCancel(waiter), deadline)
	}
	return context.WithTimeout(context.WithoutCancel(waiter), ipdbOneDefaultTimeout)
}

func (c *IPDBOneClient) shouldRetryTokenFlight(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var flightErr *ipdbOneTokenFlightDeadlineError
	if !errors.As(err, &flightErr) {
		return false
	}
	deadline, ok := ctx.Deadline()
	return ok && deadline.After(flightErr.deadline)
}

// LookupIP queries the IP information from IPDB.One
func (c *IPDBOneClient) LookupIP(ip string, lang string) (*IPGeoData, error) {
	ctx, cancel := c.timeoutContext()
	defer cancel()

	// Ensure we have a valid token
	token, err := c.ensureToken(ctx)
	if err != nil {
		return &IPGeoData{}, fmt.Errorf("ipdbone auth: %w", err)
	}

	// Map language code if needed
	langCode, ok := LangMap[lang]
	if !ok {
		langCode = "en" // Default to English
	}

	// Query the IP information
	queryURL := c.config.BaseURL + "/query/" + ip + "?lang=" + langCode

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, queryURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "NextTrace/"+config.Version)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	statusCode := gjson.Get(string(body), "code").Int()
	if statusCode != 200 {
		return nil, errors.New("failed to get IP info: " + gjson.Get(string(body), "message").String())
	}

	return parseIPDBOneResponse(ip, body)
}

func (c *IPDBOneClient) timeoutContext() (context.Context, context.CancelFunc) {
	if timeout := c.httpClient.Timeout; timeout > 0 {
		return context.WithTimeout(context.Background(), timeout)
	}
	return context.WithCancel(context.Background())
}

// parseIPDBOneResponse converts the API response to an IPGeoData struct
func parseIPDBOneResponse(ip string, responseBody []byte) (*IPGeoData, error) {
	data := gjson.Get(string(responseBody), "data")
	result := &IPGeoData{
		IP: ip,
	}
	parseIPDBOneGeo(data.Get("geo"), result)
	parseIPDBOneRouting(data.Get("routing"), result)
	return result, nil
}

func hasJSONValue(result gjson.Result) bool {
	return result.Exists() && result.Type != gjson.Null
}

func parseIPDBOneGeo(geoData gjson.Result, result *IPGeoData) {
	if result == nil || !geoData.Exists() {
		return
	}

	coordinate := geoData.Get("coordinate")
	if hasJSONValue(coordinate) && coordinate.IsArray() && len(coordinate.Array()) >= 2 {
		result.Lat = coordinate.Array()[0].Float()
		result.Lng = coordinate.Array()[1].Float()
	}

	if country := geoData.Get("country"); hasJSONValue(country) {
		result.Country = country.String()
	}
	if region := geoData.Get("region"); hasJSONValue(region) {
		result.Prov = region.String()
	}
	if city := geoData.Get("city"); hasJSONValue(city) {
		result.City = city.String()
	}
}

func parseIPDBOneRouting(routingData gjson.Result, result *IPGeoData) {
	if result == nil || !routingData.Exists() {
		return
	}

	asnData := routingData.Get("asn")
	if number := asnData.Get("number"); hasJSONValue(number) {
		result.Asnumber = strconv.FormatInt(number.Int(), 10)
	}
	if asnName := routingData.Get("asn.name"); hasJSONValue(asnName) {
		result.Owner = asnName.String()
	}
	if domain := routingData.Get("asn.domain"); hasJSONValue(domain) {
		result.Owner = domain.String()
	}
	if asName := routingData.Get("asn.asname"); hasJSONValue(asName) {
		result.Whois = asName.String()
	}
}

// Global client instance for backward compatibility
var defaultClient = NewIPDBOneClient()

// IPDBOne looks up IP information from IPDB.One (maintains backward compatibility)
func IPDBOne(ip string, timeout time.Duration, lang string, _ bool) (*IPGeoData, error) {
	client := defaultClient.cloneWithTimeout(timeout)
	return client.LookupIP(ip, lang)
}
