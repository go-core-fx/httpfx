package httpfx

import "errors"

var (
	// ErrInvalidConfig is returned when the HTTP client configuration is invalid.
	ErrInvalidConfig = errors.New("invalid config")

	// ErrInvalidProxyURL is returned when the proxy URL cannot be parsed.
	ErrInvalidProxyURL = errors.New("invalid proxy URL")

	// ErrProxyDialFailed is returned when the proxy dialer cannot be created.
	ErrProxyDialFailed = errors.New("proxy dialer creation failed")
)
