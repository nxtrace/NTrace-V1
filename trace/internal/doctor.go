package internal

import (
	"context"
	"net"
)

type BackendOptions struct {
	Protocol                       string
	IPVersion, ICMPMode, Port, TOS int
	Source, Target                 net.IP
	Device                         string
}

type BackendCheck struct {
	Name     string
	Detail   string
	Err      error
	Unknown  bool
	Optional bool
	Skipped  bool
}

func backendStep(ctx context.Context, name string, fn func() error) BackendCheck {
	if err := ctx.Err(); err != nil {
		return BackendCheck{Name: name, Err: err, Skipped: true}
	}
	return BackendCheck{Name: name, Err: fn()}
}
