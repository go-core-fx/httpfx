package httpfx

import "errors"

var (
	// ErrInvalidConfig is returned when the HTTP client configuration is invalid.
	ErrInvalidConfig = errors.New("invalid config")

	// ErrInvalidProxyURL is returned when the proxy URL cannot be parsed.
	ErrInvalidProxyURL = errors.New("invalid proxy URL")

	// ErrProxyDialFailed is returned when the proxy dialer cannot be created.
	ErrProxyDialFailed = errors.New("proxy dialer creation failed")

	// ErrCertPoolFailed is returned when a root CA file cannot be read or the
	// root CA certificate pool cannot be built.
	ErrCertPoolFailed = errors.New("root CA cert pool creation failed")

	// ErrEmptyCertPEM is returned when PEM data contains no valid certificates.
	ErrEmptyCertPEM = errors.New("no valid certificates found in PEM data")
)
