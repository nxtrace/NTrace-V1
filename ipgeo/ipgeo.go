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
	switch strings.ToUpper(CanonicalizeNextTraceAPIProvider(s)) {
	case "DN42":
		return DN42
	case "NEXTTRACE-API":
		return NextTraceAPISource()
	case "IP.SB":
		return IPSB
	case "IPINSIGHT":
		return IPInSight
	case "IPAPI.COM":
		return IPApiCom
	case "IP-API.COM":
		return IPApiCom
	case "IPINFO":
		return IPInfo
	case "IPINFOLOCAL":
		return IPInfoLocal
	case "CHUNZHEN":
		return Chunzhen
	case "DISABLE-GEOIP":
		return disableGeoIP
	case "IPDB.ONE":
		return IPDBOne
	default:
		return NextTraceAPISource()
	}
}

func GetSourceWithGeoDNS(s string, dotServer string) Source {
	base := GetSource(s)
	dotServer = strings.TrimSpace(strings.ToLower(dotServer))
	if base == nil {
		return base
	}
	return func(ip string, timeout time.Duration, lang string, maptrace bool) (*IPGeoData, error) {
		return util.WithGeoDNSResolver(dotServer, func() (*IPGeoData, error) {
			return base(ip, timeout, lang, maptrace)
		})
	}
}

func disableGeoIP(string, time.Duration, string, bool) (*IPGeoData, error) {
	return &IPGeoData{}, nil
}
