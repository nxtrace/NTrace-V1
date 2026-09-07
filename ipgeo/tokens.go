package ipgeo

import "github.com/nxtrace/NTrace-core/util"

type tokenData struct {
	ipinsight    string
	ipinfo       string
	nextTraceAPI string
	baseUrl      string
}

func (t *tokenData) BaseOrDefault(def string) string {
	if t.baseUrl == "" {
		return def
	}
	return t.baseUrl
}

var token = tokenData{
	ipinsight:    util.GetSecretEnvDefault("NEXTTRACE_IPINSIGHT_TOKEN", ""),
	ipinfo:       util.GetSecretEnvDefault("NEXTTRACE_IPINFO_TOKEN", ""),
	baseUrl:      util.GetEnvDefault("NEXTTRACE_IPAPI_BASE", ""),
	nextTraceAPI: "NextTraceDemo",
}
