package httpfx

import "time"

// Option configures per-client overrides on [Factory.NewClient].
type Option func(*clientOptions)

type clientOptions struct {
	proxyURL            *string
	proxyFromEnv        *bool
	bypass              *string
	timeout             *time.Duration
	maxIdleConns        *int
	maxIdleConnsPerHost *int
	idleConnTimeout     *time.Duration
	rootCAFile          *string
	rootCAPEM           *string
	rootCAReplaceSystem *bool
}

func (o *clientOptions) apply(base Config) Config {
	cfg := base

	if o.proxyURL != nil {
		cfg.ProxyURL = *o.proxyURL
	}

	if o.proxyFromEnv != nil {
		cfg.ProxyFromEnv = *o.proxyFromEnv
	}

	if o.bypass != nil {
		cfg.Bypass = *o.bypass
	}

	if o.timeout != nil {
		cfg.Timeout = *o.timeout
	}

	if o.maxIdleConns != nil {
		cfg.MaxIdleConns = *o.maxIdleConns
	}

	if o.maxIdleConnsPerHost != nil {
		cfg.MaxIdleConnsPerHost = *o.maxIdleConnsPerHost
	}

	if o.idleConnTimeout != nil {
		cfg.IdleConnTimeout = *o.idleConnTimeout
	}

	if o.rootCAFile != nil {
		cfg.TLS.RootCAFile = *o.rootCAFile
	}

	if o.rootCAPEM != nil {
		cfg.TLS.RootCAPEM = *o.rootCAPEM
	}

	if o.rootCAReplaceSystem != nil {
		cfg.TLS.RootCAReplaceSystem = *o.rootCAReplaceSystem
	}

	return cfg
}

// WithProxyURL overrides the SOCKS5 proxy URL for this client.
func WithProxyURL(rawURL string) Option {
	return func(o *clientOptions) { o.proxyURL = &rawURL }
}

// WithProxyFromEnv overrides the ProxyFromEnv flag for this client.
func WithProxyFromEnv(v bool) Option {
	return func(o *clientOptions) { o.proxyFromEnv = &v }
}

// WithBypass overrides the proxy bypass list for this client.
func WithBypass(bypass string) Option {
	return func(o *clientOptions) { o.bypass = &bypass }
}

// WithTimeout overrides the client-level timeout for this client.
func WithTimeout(t time.Duration) Option {
	return func(o *clientOptions) { o.timeout = &t }
}

// WithMaxIdleConns overrides the maximum idle connections for this client.
func WithMaxIdleConns(n int) Option {
	return func(o *clientOptions) { o.maxIdleConns = &n }
}

// WithMaxIdleConnsPerHost overrides the maximum idle connections per host for this client.
func WithMaxIdleConnsPerHost(n int) Option {
	return func(o *clientOptions) { o.maxIdleConnsPerHost = &n }
}

// WithIdleConnTimeout overrides the idle connection timeout for this client.
func WithIdleConnTimeout(t time.Duration) Option {
	return func(o *clientOptions) { o.idleConnTimeout = &t }
}

// WithRootCAFile overrides the root CA certificate file path for this client.
// The file must contain PEM-encoded certificates; all of them are added to
// the trust pool. An empty path clears the base configuration's CA file.
func WithRootCAFile(path string) Option {
	return func(o *clientOptions) { o.rootCAFile = &path }
}

// WithRootCAPEM overrides the inline PEM-encoded root CA data for this
// client. Multiple certificates in one string are all added to the trust
// pool. An empty string clears the base configuration's CA PEM data.
func WithRootCAPEM(pem string) Option {
	return func(o *clientOptions) { o.rootCAPEM = &pem }
}

// WithRootCAReplaceSystem overrides whether this client replaces the system
// certificate pool instead of appending to it. When true, only the root CAs
// configured for this client are trusted.
func WithRootCAReplaceSystem(replace bool) Option {
	return func(o *clientOptions) { o.rootCAReplaceSystem = &replace }
}
