//go:build flavor_tiny

package cmd

const (
	appBinName       = "nexttrace-tiny"
	enableWebUI      = false
	enableGlobalping = false
	enableTraceroute = true
	enableMTR        = true
	enableMTU        = true
	enableSpeed      = false
	enableNali       = false
	defaultMTR       = false
)
