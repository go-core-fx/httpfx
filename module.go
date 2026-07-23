package httpfx

import (
	"net/http"

	"github.com/go-core-fx/logger"
	"go.uber.org/fx"
)

const ModuleName = "httpfx"

func Module() fx.Option {
	return fx.Module(
		ModuleName,
		logger.WithNamedLogger(ModuleName),
		fx.Provide(NewFactory),
		fx.Provide(func(f Factory) *http.Client {
			return f.NewClient()
		}),
	)
}
