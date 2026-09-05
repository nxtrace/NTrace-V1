package ipgeo

import (
	"testing"

	"github.com/nxtrace/NTrace-core/util"
)

func isolateNextTraceAPIV4ProxyEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(key, "")
	}
}

func isolateNextTraceAPIV4ProxyState(t *testing.T) {
	t.Helper()
	isolateNextTraceAPIV4ProxyEnv(t)
	oldProxy := util.EnvProxyURL
	util.EnvProxyURL = ""
	t.Cleanup(func() {
		util.EnvProxyURL = oldProxy
	})
}
