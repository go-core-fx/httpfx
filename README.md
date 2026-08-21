<a id="readme-top"></a>

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![Apache 2.0 License][license-shield]][license-url]

<br />
<div align="center">
  <h1>httpfx</h1>
  <p>
    Uber Fx module for <code>net/http.Client</code> with SOCKS5 and environment-based proxy support, plus custom root CA trust.
  </p>
  <a href="https://github.com/go-core-fx/httpfx/issues/new">Report Bug</a>
  &middot;
  <a href="https://github.com/go-core-fx/httpfx/issues/new">Request Feature</a>
</div>

## Table of Contents
- [Table of Contents](#table-of-contents)
- [About The Project](#about-the-project)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
  - [Module Setup](#module-setup)
  - [Configuration Reference](#configuration-reference)
  - [Factory \& Per-Client Options](#factory--per-client-options)
    - [Available Options](#available-options)
  - [Proxy Examples](#proxy-examples)
  - [TLS \& Root CA Examples](#tls--root-ca-examples)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)


---

## About The Project

`httpfx` is an [Uber Fx](https://uber-go.github.io/fx/) module that provides a configured `*http.Client` and a `Factory` for creating additional client instances. It supports:

- **SOCKS5 proxy** via `golang.org/x/net/proxy` (`socks5://user:pass@host:port`)
- **Environment-based proxy** via `ALL_PROXY` env var (read by `golang.org/x/net/proxy`)
- **Per-host proxy bypass** for hosts that should connect directly
- **Custom root CA trust**: append internal/corporate CAs to the system pool or replace it
- **Per-client overrides** via functional options on the `Factory`
- **Transport tuning** — idle connections, timeouts, pool sizes

### Built With

- [![Go](https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev/)
- [![Uber Fx](https://img.shields.io/badge/Uber%20Fx-000000?style=for-the-badge)](https://uber-go.github.io/fx/)
- [![x/net](https://img.shields.io/badge/golang.org%2Fx%2Fnet-000000?style=for-the-badge)](https://pkg.go.dev/golang.org/x/net/proxy)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Getting Started

### Prerequisites

- Go 1.25+
- An application using [Uber Fx](https://uber-go.github.io/fx/) for dependency injection

### Installation

```sh
go get github.com/go-core-fx/httpfx@latest
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Usage

### Module Setup

```go
import (
    "time"

    "github.com/go-core-fx/httpfx"
    "go.uber.org/fx"
)

func main() {
    fx.New(
        fx.Provide(func() httpfx.Config {
            return httpfx.Config{
                ProxyURL: "socks5://127.0.0.1:1080",
                Bypass:   "localhost,127.0.0.1",
                Timeout:  30 * time.Second,
            }
        }),
        httpfx.Module(),
        // ... other modules
    ).Run()
}
```

The module provides both a default `*http.Client` and a `Factory` for creating additional clients.

### Configuration Reference

| Field                     | Type            | Default | Description                                                                       |
| ------------------------- | --------------- | ------- | --------------------------------------------------------------------------------- |
| `ProxyURL`                | `string`        | `""`    | SOCKS5 proxy URL (e.g. `socks5://user:pass@host:port`). Takes highest precedence. |
| `ProxyFromEnv`            | `bool`          | `false` | Read proxy from `ALL_PROXY` env var when `ProxyURL` is empty.                     |
| `Bypass`                  | `string`        | `""`    | Comma-separated hosts to bypass the proxy (e.g. `localhost,127.0.0.1`).           |
| `Timeout`                 | `time.Duration` | `0`     | Client-level request timeout. Zero means no timeout.                              |
| `MaxIdleConns`            | `int`           | `0`     | Maximum idle (keep-alive) connections. Zero means no limit.                       |
| `MaxIdleConnsPerHost`     | `int`           | `0`     | Maximum idle connections per host. Zero means Go default (2).                     |
| `IdleConnTimeout`         | `time.Duration` | `0`     | Maximum time a connection stays idle. Zero means no timeout.                      |
| `TLS.RootCAFile`          | `string`        | `""`    | Path to a PEM-encoded root CA file. Appended to the system pool unless replaced.  |
| `TLS.RootCAPEM`           | `string`        | `""`    | Inline PEM-encoded root CA data. Merged with `TLS.RootCAFile` when both are set.  |
| `TLS.RootCAReplaceSystem` | `bool`          | `false` | When true, replace the system pool; only the configured root CAs are trusted.     |

**Proxy precedence:** `ProxyURL` → `ProxyFromEnv`. To disable all proxying, clear `ProxyURL` and set `ProxyFromEnv: false`.

> **Platform note:** append mode builds on `x509.SystemCertPool()`, which returns an empty pool on
> macOS/darwin (system roots load lazily at verify time), so append-mode behavior can differ by
> platform. Replace mode always trusts exactly the configured CAs.

### Factory & Per-Client Options

Inject `httpfx.Factory` to create additional clients with shared base config but per-client overrides:

```go
func Handler(f httpfx.Factory) error {
    // Default client — uses factory base config
    defaultClient, err := f.NewClient()
    if err != nil {
        return err
    }

    // Override timeout for a fast endpoint
    apiClient, err := f.NewClient(httpfx.WithTimeout(5 * time.Second))
    if err != nil {
        return err
    }

    // Disable proxy for internal service calls
    internalClient, err := f.NewClient(httpfx.WithProxyURL(""))
    if err != nil {
        return err
    }

    // Custom transport for a specific module
    uploadClient, err := f.NewClient(
        httpfx.WithTimeout(5 * time.Minute),
        httpfx.WithMaxIdleConns(10),
    )
    if err != nil {
        return err
    }

    _ = defaultClient
    _ = apiClient
    _ = internalClient
    _ = uploadClient

    return nil
}
```

#### Available Options

| Option                       | Description                            |
| ---------------------------- | -------------------------------------- |
| `WithProxyURL(url)`          | Override SOCKS5 proxy URL              |
| `WithProxyFromEnv(v)`        | Override env-based proxy flag          |
| `WithBypass(bypass)`         | Override proxy bypass list             |
| `WithTimeout(d)`             | Override client timeout                |
| `WithMaxIdleConns(n)`        | Override max idle connections          |
| `WithMaxIdleConnsPerHost(n)` | Override max idle connections per host |
| `WithIdleConnTimeout(d)`     | Override idle connection timeout       |
| `WithRootCAFile(path)`       | Override root CA certificate file path |
| `WithRootCAPEM(pem)`         | Override inline PEM root CA data       |
| `WithRootCAReplaceSystem(v)` | Override system-pool replacement flag  |

### Proxy Examples

All proxying goes through `golang.org/x/net/proxy`: an explicit `socks5://` URL or the `ALL_PROXY` environment variable. Plain HTTP CONNECT proxies (`http://proxy:8080`) are not supported.

**SOCKS5 with authentication:**

```go
httpfx.Config{
    ProxyURL: "socks5://user:pass@127.0.0.1:1080",
}
```

**Environment-based (reads `ALL_PROXY`):**

```go
httpfx.Config{
    ProxyFromEnv: true,
}
```

```sh
export ALL_PROXY="socks5://127.0.0.1:1080"
```

**SOCKS5 with bypass for local addresses and CIDR ranges:**

```go
httpfx.Config{
    ProxyURL: "socks5://127.0.0.1:1080",
    Bypass:   "localhost,127.0.0.1,192.168.0.0/16",
}
```

### TLS & Root CA Examples

By default, clients trust the system certificate pool. To trust an internal or corporate CA, configure `Config.TLS`; configured CAs are appended to the system pool unless `RootCAReplaceSystem` is set.

**Internal CA via file path (Config literal):**

```go
httpfx.Config{
    TLS: httpfx.TLSConfig{
        RootCAFile: "/etc/corp/root-ca.pem",
    },
}
```

**Inline PEM data (merged with the file when both are set):**

```go
httpfx.Config{
    TLS: httpfx.TLSConfig{
        RootCAFile: "/etc/corp/root-ca.pem",
        RootCAPEM:  "<PEM-encoded certificate data>",
    },
}
```

**Replace mode - trust ONLY the configured CAs (strict internal environments):**

```go
httpfx.Config{
    TLS: httpfx.TLSConfig{
        RootCAFile:          "/etc/corp/root-ca.pem",
        RootCAReplaceSystem: true,
    },
}
```

**Same settings via Factory per-client options:**

```go
corpClient, err := f.NewClient(
    httpfx.WithRootCAFile("/etc/corp/root-ca.pem"),
)
if err != nil {
    return err
}

strictClient, err := f.NewClient(
    httpfx.WithRootCAPEM(pemData),
    httpfx.WithRootCAReplaceSystem(true),
)
if err != nil {
    return err
}
```

Notes:

- Zero-value `httpfx.Config{}` keeps the default Go TLS behavior (system roots only).
- Invalid CA configuration (missing file, invalid PEM) makes `Factory.NewClient` return an error; when clients are built through `Module`, application startup fails with that error.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Roadmap

- [x] SOCKS5 proxy support via `golang.org/x/net/proxy`
- [x] Environment-based proxy (`ALL_PROXY`)
- [x] Per-host proxy bypass
- [x] Factory with per-client functional options
- [x] Transport tuning (idle connections, timeouts)
- [x] TLS configuration options
- [ ] Proxy authentication header support

See the [open issues](https://github.com/go-core-fx/httpfx/issues) for a full list of proposed features.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## License

Distributed under the Apache License 2.0. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

## Acknowledgments

- [Uber Fx](https://uber-go.github.io/fx/) — dependency injection framework
- [golang.org/x/net/proxy](https://pkg.go.dev/golang.org/x/net/proxy) — SOCKS5 and environment-based proxy dialers
- [Best-README-Template](https://github.com/othneildrew/Best-README-Template) — README structure

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
[contributors-shield]: https://img.shields.io/github/contributors/go-core-fx/httpfx.svg?style=for-the-badge
[contributors-url]: https://github.com/go-core-fx/httpfx/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/go-core-fx/httpfx.svg?style=for-the-badge
[forks-url]: https://github.com/go-core-fx/httpfx/network/members
[stars-shield]: https://img.shields.io/github/stars/go-core-fx/httpfx.svg?style=for-the-badge
[stars-url]: https://github.com/go-core-fx/httpfx/stargazers
[issues-shield]: https://img.shields.io/github/issues/go-core-fx/httpfx.svg?style=for-the-badge
[issues-url]: https://github.com/go-core-fx/httpfx/issues
[license-shield]: https://img.shields.io/github/license/go-core-fx/httpfx.svg?style=for-the-badge
[license-url]: https://github.com/go-core-fx/httpfx/blob/master/LICENSE
