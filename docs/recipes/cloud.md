# Cloud and network

Copy into the `allow` array of your `config.toml`. The baseline denies
`curl … | sh` and `wget … | sh` regardless, so these entries allow fetching
without allowing pipe-to-shell.

```toml
  # Cloud / security scanning
  'curl\b',
  'wget\b',
  'aws\b',
  'trivy\b',
```

`AWS_PROFILE=… aws …` and similar assignment prefixes need no entry. The AWS
config-file variables (AWS_CONFIG_FILE, AWS_SHARED_CREDENTIALS_FILE) are
sensitive and stay gated.
