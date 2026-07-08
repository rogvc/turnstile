# Containers and Kubernetes

Copy into the `allow` array of your `config.toml`. The baseline already denies
`docker run` host volume mounts and `--privileged`; `kubectl delete` and
`helm uninstall` are worth adding to your own deny list.

```toml
  # Docker  (volume-mount and --privileged patterns live in deny)
  'docker\b',

  # Kubernetes / Helm  (delete/uninstall live in deny)
  'kubectl\b',
  'helm\b',
```

To allow host mounts under a specific prefix, use `safe_path_exemptions` rather
than loosening the deny pattern; see [configuration](../configuration.md).
KUBECONFIG is sensitive and stays gated.
