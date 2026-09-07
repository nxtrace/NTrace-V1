//go:build !linux && !darwin && !windows

package doctor

import (
	"context"
	"errors"
	"github.com/nxtrace/NTrace-core/trace"
)

func queryRoute(context.Context, trace.Method, trace.Config) (Route, error) {
	return Route{}, errors.New("route query is not supported on this platform")
}
