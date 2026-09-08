// Package mtrsession stores explicitly recorded MTR sessions for offline replay.
package mtrsession

import (
	"time"

	"github.com/nxtrace/NTrace-core/trace"
)

const (
	FormatName    = "nexttrace-mtr-session"
	SchemaVersion = 1
	// MaxLineBytes includes the terminating newline written by Writer.
	MaxLineBytes = 1 << 20
	StartEvent   = "start"
	EndEvent     = "end"
)

// Parameters contains effective probe settings, never provider credentials.
type Parameters struct {
	FWMark           *uint32 `json:"fwmark,omitempty"`
	MaxPerHop        int     `json:"max_per_hop"`
	HopIntervalMs    int     `json:"hop_interval_ms"`
	TimeoutMs        int64   `json:"timeout_ms"`
	BeginHop         int     `json:"begin_hop"`
	MaxHops          int     `json:"max_hops"`
	ParallelRequests int     `json:"parallel_requests"`
	SourceAddress    string  `json:"source_address"`
	SourceDevice     string  `json:"source_device,omitempty"`
	SourcePort       *int    `json:"source_port,omitempty"`
	Port             *int    `json:"port,omitempty"`
	PacketSize       int     `json:"packet_size"`
	RandomPacketSize bool    `json:"random_packet_size"`
	TOS              int     `json:"tos"`
	ICMPMode         *int    `json:"icmp_mode,omitempty"`
	DataProvider     string  `json:"data_provider"`
	Language         string  `json:"language"`
	DotServer        string  `json:"dot_server,omitempty"`
	RDNS             bool    `json:"rdns"`
	AlwaysWaitRDNS   bool    `json:"always_wait_rdns"`
	DisableMPLS      bool    `json:"disable_mpls"`
	DN42             bool    `json:"dn42"`
}

type DisplayParameters struct {
	HostMode     int    `json:"host_mode"`
	HostNameMode int    `json:"host_name_mode"`
	ShowIPs      bool   `json:"show_ips"`
	ShowMPLS     bool   `json:"show_mpls"`
	Wide         bool   `json:"wide"`
	Columns      string `json:"columns,omitempty"`
}

type Session struct {
	Version             string            `json:"version"`
	Target              string            `json:"target"`
	ResolvedIP          string            `json:"resolved_ip"`
	Protocol            string            `json:"protocol"`
	StartedAt           time.Time         `json:"started_at"`
	EffectiveParameters *Parameters       `json:"effective_parameters"`
	SourceHost          string            `json:"source_host"`
	SourceIP            string            `json:"source_ip,omitempty"`
	Display             DisplayParameters `json:"display"`
}

type Error struct {
	Stage   string `json:"stage"`
	Message string `json:"message"`
}

type End struct {
	EndedAt   time.Time         `json:"ended_at"`
	EndReason string            `json:"end_reason"`
	PathEnd   *trace.StopReason `json:"path_end"`
	Error     *Error            `json:"error,omitempty"`
	Signal    string            `json:"signal,omitempty"`
}

// Record keeps event occurrence time separate from the ordered playback clock.
// Sequence and ElapsedNS are monotonic, even if the wall clock moves backwards.
type Record struct {
	Format        string    `json:"format"`
	SchemaVersion int       `json:"schema_version"`
	Seq           uint64    `json:"seq"`
	ElapsedNS     int64     `json:"elapsed_ns"`
	Timestamp     time.Time `json:"timestamp"`
	ProbeAgeNS    *int64    `json:"probe_age_ns,omitempty"`
	trace.MTRSessionEvent
	Session *Session `json:"session,omitempty"`
	End     *End     `json:"end,omitempty"`
}
