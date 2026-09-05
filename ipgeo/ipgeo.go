package ipgeo

import (
	"strings"
	"time"

	"github.com/nxtrace/NTrace-core/util"
)

type IPGeoData struct {
	IP        string              `json:"ip"`
	Asnumber  string              `json:"asnumber"`
	Country   string              `json:"country"`
	CountryEn string              `json:"country_en"`
	Prov      string              `json:"prov"`
	ProvEn    string              `json:"prov_en"`
	City      string              `json:"city"`
	CityEn    string              `json:"city_en"`
	District  string              `json:"district"`
	Owner     string              `json:"owner"`
	Isp       string              `json:"isp"`
	Domain    string              `json:"domain"`
	Whois     string              `json:"whois"`
	Lat       float64             `json:"lat"`
	Lng       float64             `json:"lng"`
	Prefix    string              `json:"prefix"`
	Router    map[string][]string `json:"router"`
	Source    string              `json:"source"`
}

type Source = func(ip string, timeout time.Duration, lang string, maptrace bool) (*IPGeoData, error)

// SourceDescriptor identifies a Source and the backend state that affects its
// results. Namespace is empty only for descriptors constructed by callers.
type SourceDescriptor struct {
	Source        Source
	Namespace     string
	Backend       string
	Generation    uint64
	HasGeneration bool
	// GeoDNSResolver identifies an explicitly wrapped resolver scope, including
	// the empty system resolver. It separates in-flight work, not cached values.
	GeoDNSResolver    string
	HasGeoDNSResolver bool
}

// SourceDescriptorSession returns a descriptor whose Source and generation
// belong to the same provider snapshot. Refresh is nil for static providers.
type SourceDescriptorSession struct {
	Current func() SourceDescriptor
	Refresh func()
}

// SourceSession pins any provider state used by Source. Refresh is non-nil only
// for providers whose snapshot can change during a long-lived session.
type SourceSession struct {
	Source  Source
	Refresh func()
}

const (
	// NextTraceAPIProvider is the canonical user-facing provider value for the official API.
	NextTraceAPIProvider = "NextTrace-API"

	// SourceNamespaceNextTraceAPI identifies the official NextTrace GeoIP service.
	SourceNamespaceNextTraceAPI = "nexttrace-api"
	// SourceNamespaceIPAPI identifies both IPAPI.com and ip-api.com aliases.
	SourceNamespaceIPAPI = "ip-api.com"
	// SourceNamespaceIPSB identifies the IP.SB provider.
	SourceNamespaceIPSB = "ip.sb"
	// SourceNamespaceIPInsight identifies the IPInsight provider.
	SourceNamespaceIPInsight = "ipinsight"
	// SourceNamespaceIPInfo identifies the IPInfo provider.
	SourceNamespaceIPInfo = "ipinfo"
	// SourceNamespaceIPInfoLocal identifies the local IPInfo database.
	SourceNamespaceIPInfoLocal = "ipinfolocal"
	// SourceNamespaceChunzhen identifies the local Chunzhen database.
	SourceNamespaceChunzhen = "chunzhen"
	// SourceNamespaceIPDBOne identifies the IPDB.One provider.
	SourceNamespaceIPDBOne = "ipdb.one"
	// SourceNamespaceDisableGeoIP identifies the no-op GeoIP provider.
	SourceNamespaceDisableGeoIP = "disable-geoip"
	// SourceNamespaceDN42 identifies the DN42 GeoFeed provider.
	SourceNamespaceDN42 = "dn42"

	// SourceBackendNextTraceAPIV3 identifies the WebSocket API implementation.
	SourceBackendNextTraceAPIV3 = "v3-websocket"
	// SourceBackendNextTraceAPIV4 identifies the HTTP API implementation.
	SourceBackendNextTraceAPIV4 = "v4-http"
	// SourceBackendDN42GeoFeed identifies the DN42 GeoFeed implementation.
	SourceBackendDN42GeoFeed = "geofeed"
)

// CanonicalizeNextTraceAPIProvider maps current and legacy official API names to the canonical value.
func CanonicalizeNextTraceAPIProvider(provider string) string {
	switch strings.ToUpper(strings.TrimSpace(provider)) {
	case "NEXTTRACE-API", "LEOMOEAPI", "LEOMOE":
		return NextTraceAPIProvider
	default:
		return provider
	}
}

// IsNextTraceAPIProvider reports whether provider names the official API or a legacy alias.
func IsNextTraceAPIProvider(provider string) bool {
	return CanonicalizeNextTraceAPIProvider(provider) == NextTraceAPIProvider
}

func GetSource(s string) Source {
	return GetSourceDescriptor(s).Source
}

// GetSourceSession returns a source whose provider state is fixed until Refresh
// is called.
func GetSourceSession(s string) SourceSession {
	return sourceSessionFromDescriptorSession(GetSourceDescriptorSession(s))
}

func GetSourceWithGeoDNS(s string, dotServer string) Source {
	return GetSourceDescriptorWithGeoDNS(s, dotServer).Source
}

// GetSourceSessionWithGeoDNS applies a scoped DNS policy without changing the
// session's refresh behavior.
func GetSourceSessionWithGeoDNS(s string, dotServer string) SourceSession {
	return sourceSessionFromDescriptorSession(GetSourceDescriptorSessionWithGeoDNS(s, dotServer))
}

// GetSourceDescriptor returns the current descriptor for provider s.
func GetSourceDescriptor(s string) SourceDescriptor {
	return GetSourceDescriptorSession(s).Current()
}

// GetSourceDescriptorWithGeoDNS returns the current descriptor with a scoped
// DNS policy applied to its Source.
func GetSourceDescriptorWithGeoDNS(s string, dotServer string) SourceDescriptor {
	return GetSourceDescriptorSessionWithGeoDNS(s, dotServer).Current()
}

// GetSourceDescriptorSession returns a provider session with canonical cache
// identity metadata.
func GetSourceDescriptorSession(s string) SourceDescriptorSession {
	return getSourceDescriptorSession(s, "", false)
}

// GetSourceDescriptorSessionWithGeoDNS applies a scoped DNS policy without
// changing descriptor identity or refresh behavior.
func GetSourceDescriptorSessionWithGeoDNS(s string, dotServer string) SourceDescriptorSession {
	dotServer = strings.TrimSpace(strings.ToLower(dotServer))
	return getSourceDescriptorSession(s, dotServer, true)
}

func getSourceDescriptorSession(s string, dotServer string, withGeoDNS bool) SourceDescriptorSession {
	if sourceSelector(s) == "DN42" {
		return newDN42SourceDescriptorSession(dotServer, withGeoDNS)
	}

	descriptor := sourceDescriptor(s)
	descriptor = applyGeoDNS(descriptor, dotServer, withGeoDNS)
	return SourceDescriptorSession{
		Current: func() SourceDescriptor { return descriptor },
	}
}

func sourceDescriptor(s string) SourceDescriptor {
	switch sourceSelector(s) {
	case "NEXTTRACE-API":
		return nextTraceAPISourceDescriptor()
	case "IP.SB":
		return staticSourceDescriptor(IPSB, SourceNamespaceIPSB)
	case "IPINSIGHT":
		return staticSourceDescriptor(IPInSight, SourceNamespaceIPInsight)
	case "IPAPI.COM", "IP-API.COM":
		return staticSourceDescriptor(IPApiCom, SourceNamespaceIPAPI)
	case "IPINFO":
		return staticSourceDescriptor(IPInfo, SourceNamespaceIPInfo)
	case "IPINFOLOCAL":
		return staticSourceDescriptor(IPInfoLocal, SourceNamespaceIPInfoLocal)
	case "CHUNZHEN":
		return staticSourceDescriptor(Chunzhen, SourceNamespaceChunzhen)
	case "DISABLE-GEOIP":
		return staticSourceDescriptor(disableGeoIP, SourceNamespaceDisableGeoIP)
	case "IPDB.ONE":
		return staticSourceDescriptor(IPDBOne, SourceNamespaceIPDBOne)
	default:
		return nextTraceAPISourceDescriptor()
	}
}

func sourceSelector(provider string) string {
	return strings.ToUpper(strings.TrimSpace(CanonicalizeNextTraceAPIProvider(provider)))
}

func nextTraceAPISourceDescriptor() SourceDescriptor {
	if NextTraceAPIV4TokenConfigured() {
		return SourceDescriptor{
			Source:    NextTraceAPIV4GeoIP,
			Namespace: SourceNamespaceNextTraceAPI,
			Backend:   SourceBackendNextTraceAPIV4,
		}
	}
	return SourceDescriptor{
		Source:    NextTraceAPIV3GeoIP,
		Namespace: SourceNamespaceNextTraceAPI,
		Backend:   SourceBackendNextTraceAPIV3,
	}
}

func staticSourceDescriptor(source Source, namespace string) SourceDescriptor {
	return SourceDescriptor{Source: source, Namespace: namespace, Backend: namespace}
}

func applyGeoDNS(descriptor SourceDescriptor, dotServer string, enabled bool) SourceDescriptor {
	source := descriptor.Source
	if source == nil || !enabled {
		return descriptor
	}
	dotServer = strings.ToLower(strings.TrimSpace(dotServer))
	descriptor.GeoDNSResolver = dotServer
	descriptor.HasGeoDNSResolver = true
	descriptor.Source = func(ip string, timeout time.Duration, lang string, maptrace bool) (*IPGeoData, error) {
		return util.WithGeoDNSResolver(dotServer, func() (*IPGeoData, error) {
			return source(ip, timeout, lang, maptrace)
		})
	}
	return descriptor
}

func sourceSessionFromDescriptorSession(session SourceDescriptorSession) SourceSession {
	current := session.Current()
	if session.Refresh == nil {
		return SourceSession{Source: current.Source}
	}
	return SourceSession{
		Source: func(ip string, timeout time.Duration, lang string, maptrace bool) (*IPGeoData, error) {
			return session.Current().Source(ip, timeout, lang, maptrace)
		},
		Refresh: session.Refresh,
	}
}

func disableGeoIP(string, time.Duration, string, bool) (*IPGeoData, error) {
	return &IPGeoData{}, nil
}
