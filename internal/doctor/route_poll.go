//go:build linux || darwin

package doctor

import (
	"context"
	"github.com/nxtrace/NTrace-core/internal/routeprobe"
)

func readRouteDatagram(ctx context.Context, fd int, buf []byte) (int, error) {
	return routeprobe.ReadDatagram(ctx, fd, buf)
}
