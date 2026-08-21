package httpfx_test

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-core-fx/httpfx"
	"go.uber.org/fx"
)

// TestModuleInjectsClientTrustingCustomCA runs a full Fx application with
// [Module] and proves the injected [*http.Client] trusts a custom root CA for
// end-to-end HTTPS requests.
func TestModuleInjectsClientTrustingCustomCA(t *testing.T) {
	authority := newTestAuthority(t, "httpfx-fx-module-ca")
	serverURL := startTLSServer(t, authority)

	var client *http.Client
	app := fx.New(
		fx.NopLogger,
		fx.Supply(httpfx.Config{
			Timeout: 5 * time.Second,
			TLS:     httpfx.TLSConfig{RootCAPEM: string(authority.certPEM)},
		}),
		httpfx.Module(),
		fx.Populate(&client),
	)
	if err := app.Err(); err != nil {
		t.Fatalf("fx.New() error = %v, want successful dependency graph", err)
	}

	startCtx, cancelStart := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStart()
	if err := app.Start(startCtx); err != nil {
		t.Fatalf("app.Start() error = %v, want nil", err)
	}
	t.Cleanup(func() {
		stopCtx, cancelStop := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelStop()
		_ = app.Stop(stopCtx)
	})

	if client == nil {
		t.Fatal("injected *http.Client = nil, want factory-built client")
	}

	resp, err := client.Get(serverURL)
	if err != nil {
		t.Fatalf("HTTPS request with injected client failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// TestModuleInvalidTLSConfigFailsStartup proves that invalid CA configuration
// fails application startup with the underlying construction error instead of
// silently injecting a fallback client.
func TestModuleInvalidTLSConfigFailsStartup(t *testing.T) {
	var client *http.Client
	app := fx.New(
		fx.NopLogger,
		fx.Supply(httpfx.Config{
			TLS: httpfx.TLSConfig{RootCAFile: filepath.Join(t.TempDir(), "missing.pem")},
		}),
		httpfx.Module(),
		fx.Populate(&client),
	)

	startCtx, cancelStart := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStart()
	if err := app.Start(startCtx); !errors.Is(err, httpfx.ErrCertPoolFailed) {
		t.Fatalf("app.Start() error = %v, want wrapped httpfx.ErrCertPoolFailed", err)
	}
}
