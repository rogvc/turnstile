# Go

Copy into the `allow` array of your `config.toml`.

```toml
  # Go
  'go\b',
  'gofmt\b',
  'golint\b',
  'golangci-lint\b',
```

`GOPATH=…`, `GOROOT=…`, and `GOBIN=…` assignments need no entry. GOFLAGS,
GOPROXY, and GOENV are in `sensitive_env_var*` and stay gated.
