package httpfx

import "time"

// Config holds the HTTP client configuration.
type Config struct {
	// ProxyURL is an explicit SOCKS5 proxy URL (e.g., "socks5://user:pass@host:port").
	// Empty means no proxy. Takes precedence over ProxyFromEnv.
	ProxyURL string

	// ProxyFromEnv enables reading the proxy from the ALL_PROXY environment variable.
	// Used only when ProxyURL is empty.
	ProxyFromEnv bool

	// Bypass is a comma-separated list of hosts that bypass the proxy
	// (e.g., "localhost,127.0.0.1").
	Bypass string

	// Timeout is the HTTP client-level timeout. Zero means no timeout.
	Timeout time.Duration

	// MaxIdleConns is the maximum number of idle (keep-alive) connections.
	// Zero means no limit.
	MaxIdleConns int

	// MaxIdleConnsPerHost is the maximum idle connections per host.
	// Zero means DefaultMaxIdleConnsPerHost (2).
	MaxIdleConnsPerHost int

	// IdleConnTimeout is the maximum time an idle connection is kept alive.
	// Zero means no timeout.
	IdleConnTimeout time.Duration
}
