package httpfx

import (
	"net/http"
)

// Factory creates [http.Client] instances with shared proxy and transport configuration.
type Factory interface {
	// NewClient creates a new [http.Client] using the factory's base configuration,
	// with optional per-client overrides via [Option]. It returns an error when
	// the resulting configuration is invalid (e.g. unusable root CA settings).
	NewClient(opts ...Option) (*http.Client, error)
}

type factory struct {
	config Config
}

// NewFactory creates a new Factory from the provided configuration.
func NewFactory(config Config) Factory {
	return &factory{config: config}
}

// NewClient implements [Factory].
func (f *factory) NewClient(opts ...Option) (*http.Client, error) {
	cfg := f.config

	if len(opts) > 0 {
		co := new(clientOptions)
		for _, opt := range opts {
			opt(co)
		}

		cfg = co.apply(cfg)
	}

	return newClient(cfg)
}
