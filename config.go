package httpfx

import "time"

// Config holds the HTTP client configuration.
type Config struct {
	// ProxyURL is an explicit SOCKS5 proxy URL (e.g., "socks5://user:pass@host:port").
	// Empty means inherit [http.DefaultTransport]'s value.
	ProxyURL string

	// Bypass is a comma-separated list of hosts that bypass the proxy
	// (e.g., "localhost,127.0.0.1").
	Bypass string

	// Timeout is the HTTP client-level timeout. Zero means inherit
	// [http.DefaultClient]'s timeout (none).
	Timeout time.Duration

	// MaxIdleConns is the maximum number of idle (keep-alive) connections.
	// Zero means inherit [http.DefaultTransport]'s value.
	MaxIdleConns int

	// MaxIdleConnsPerHost is the maximum idle connections per host.
	// Zero means inherit [http.DefaultTransport]'s value.
	MaxIdleConnsPerHost int

	// IdleConnTimeout is the maximum time an idle connection is kept alive.
	// Zero means inherit [http.DefaultTransport]'s value.
	IdleConnTimeout time.Duration

	// TLS configures root CA trust for TLS connections; see [TLSConfig].
	// The zero value keeps the default behavior (system certificate pool only).
	TLS TLSConfig
}

// TLSConfig holds root CA trust configuration for TLS connections.
type TLSConfig struct {
	// RootCAFile is a path to a PEM-encoded root CA certificate file.
	// Multiple certificates in one file are all added to the pool.
	RootCAFile string

	// RootCAPEM is PEM-encoded root CA certificate data. Multiple
	// certificates in one string are all added to the pool.
	RootCAPEM string

	// RootCAReplaceSystem replaces the system certificate pool instead of
	// appending to it. When true, only the configured root CAs are trusted.
	//
	// Note: append mode relies on [x509.SystemCertPool], which returns an
	// empty pool on macOS/darwin (system roots load lazily at verify time),
	// so append-mode behavior can differ by platform. Replace mode always
	// trusts exactly the configured CAs.
	RootCAReplaceSystem bool
}
