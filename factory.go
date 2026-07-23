package httpfx

import (
	"net/http"

	"go.uber.org/zap"
)

// Factory creates [http.Client] instances with shared proxy and transport configuration.
type Factory interface {
	// NewClient creates a new [http.Client] using the factory's base configuration,
	// with optional per-client overrides via [Option].
	NewClient(opts ...Option) *http.Client
}

type factory struct {
	config Config
	logger *zap.Logger
}

// NewFactory creates a new Factory from the provided configuration.
func NewFactory(config Config, logger *zap.Logger) Factory {
	return &factory{
		config: config,
		logger: logger,
	}
}

// NewClient implements [Factory].
func (f *factory) NewClient(opts ...Option) *http.Client {
	cfg := f.config

	if len(opts) > 0 {
		co := new(clientOptions)
		for _, opt := range opts {
			opt(co)
		}

		cfg = co.apply(cfg)
	}

	client, err := newClient(cfg)
	if err != nil {
		f.logger.Error("failed to create HTTP client", zap.Error(err))

		return http.DefaultClient
	}

	return client
}
