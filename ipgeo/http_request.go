package ipgeo

import (
	"context"
	"net/http"
	"time"
)

func newGeoRequest(method, url string, timeout time.Duration) (*http.Request, context.CancelFunc, error) {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return req, cancel, nil
}
