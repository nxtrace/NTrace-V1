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

// SourceSession pins any provider state used by Source. Refresh is non-nil only
// for providers whose snapshot can change during a long-lived session.
type SourceSession struct {
	Source  Source
	Refresh func()
}

// NextTraceAPIProvider is the canonical data-provider value for the official API.
const NextTraceAPIProvider = "NextTrace-API"

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
	return GetSourceSession(s).Source
}

// GetSourceSession returns a source whose provider state is fixed until Refresh
// is called.
func GetSourceSession(s string) SourceSession {
	var source Source
	switch strings.ToUpper(CanonicalizeNextTraceAPIProvider(s)) {
	case "DN42":
		return newDN42SourceSession()
	case "NEXTTRACE-API":
		source = NextTraceAPISource()
	case "IP.SB":
		source = IPSB
	case "IPINSIGHT":
		source = IPInSight
	case "IPAPI.COM":
		source = IPApiCom
	case "IP-API.COM":
		source = IPApiCom
	case "IPINFO":
		source = IPInfo
	case "IPINFOLOCAL":
		source = IPInfoLocal
	case "CHUNZHEN":
		source = Chunzhen
	case "DISABLE-GEOIP":
		source = disableGeoIP
	case "IPDB.ONE":
		source = IPDBOne
	default:
		source = NextTraceAPISource()
	}
	return SourceSession{Source: source}
}

func GetSourceWithGeoDNS(s string, dotServer string) Source {
	return GetSourceSessionWithGeoDNS(s, dotServer).Source
}

// GetSourceSessionWithGeoDNS applies a scoped DNS policy without changing the
// session's refresh behavior.
func GetSourceSessionWithGeoDNS(s string, dotServer string) SourceSession {
	session := GetSourceSession(s)
	base := session.Source
	dotServer = strings.TrimSpace(strings.ToLower(dotServer))
	if base == nil {
		return session
	}
	session.Source = func(ip string, timeout time.Duration, lang string, maptrace bool) (*IPGeoData, error) {
		return util.WithGeoDNSResolver(dotServer, func() (*IPGeoData, error) {
			return base(ip, timeout, lang, maptrace)
		})
	}
	return session
}

func disableGeoIP(string, time.Duration, string, bool) (*IPGeoData, error) {
	return &IPGeoData{}, nil
}
