package httpfx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// buildTLSConfig builds a [*tls.Config] with a root CA pool from the provided
// [TLSConfig]. It returns (nil, nil) when no root CA source is configured so
// that the zero-value [Config] keeps the default TLS behavior.
func buildTLSConfig(tlsCfg TLSConfig) (*tls.Config, error) {
	if tlsCfg.RootCAFile == "" && tlsCfg.RootCAPEM == "" {
		return nil, nil //nolint:nilnil // zero-value config must keep default TLS behavior
	}

	pool, err := newRootCAPool(tlsCfg)
	if err != nil {
		return nil, err
	}

	return &tls.Config{RootCAs: pool}, nil //nolint:exhaustruct // only trust root is customized
}

// newRootCAPool builds the root CA pool. Unless RootCAReplaceSystem is set,
// custom CAs are appended to a copy of the system pool; if the system pool
// cannot be loaded, a fresh pool is used as fallback.
func newRootCAPool(tlsCfg TLSConfig) (*x509.CertPool, error) {
	pool := baseCertPool(tlsCfg.RootCAReplaceSystem)

	if tlsCfg.RootCAFile != "" {
		if err := appendCAPEMFile(pool, tlsCfg.RootCAFile); err != nil {
			return nil, err
		}
	}

	if tlsCfg.RootCAPEM != "" {
		if err := appendCAPEM(pool, []byte(tlsCfg.RootCAPEM)); err != nil {
			return nil, err
		}
	}

	return pool, nil
}

// baseCertPool returns the pool to append custom CAs to: a fresh empty pool
// when replacing the system pool, otherwise a copy of the system pool with a
// fresh-pool fallback if the system pool is unavailable.
func baseCertPool(replaceSystem bool) *x509.CertPool {
	if replaceSystem {
		return x509.NewCertPool()
	}

	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// System pool unavailable (e.g., minimal containers); start fresh.
		return x509.NewCertPool()
	}

	return pool
}

// appendCAPEMFile reads a PEM-encoded CA file and appends its certificates to
// the pool. Read failures wrap [ErrCertPoolFailed]; PEM without any valid
// certificate wraps [ErrEmptyCertPEM].
func appendCAPEMFile(pool *x509.CertPool, path string) error {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: reading root CA file: %w", ErrCertPoolFailed, err)
	}

	return appendCAPEM(pool, pemBytes)
}

// appendCAPEM appends all certificates from PEM data to the pool. It returns
// an error wrapping [ErrEmptyCertPEM] when no valid certificate is found.
func appendCAPEM(pool *x509.CertPool, pemBytes []byte) error {
	if !pool.AppendCertsFromPEM(pemBytes) {
		return fmt.Errorf("%w", ErrEmptyCertPEM)
	}

	return nil
}
