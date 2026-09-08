//go:build !darwin && !(windows && amd64)

package internal

import "context"

func checkTCPCapture(context.Context, *TCPSpec) []BackendCheck { return nil }
func checkUDPCapture(context.Context, *UDPSpec) []BackendCheck { return nil }
