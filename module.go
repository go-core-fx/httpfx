package httpfx

import (
	"net/http"

	"go.uber.org/fx"
)

const ModuleName = "httpfx"

func Module() fx.Option {
	return fx.Module(
		ModuleName,
		fx.Provide(NewFactory),
		fx.Provide(func(f Factory) (*http.Client, error) {
			return f.NewClient()
		}),
	)
}
