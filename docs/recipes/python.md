# Python

Copy into the `allow` array of your `config.toml`.

```toml
  # Python
  'python3?\b',
  'pip3?\b',
  'pip\b',
  'pytest\b',
  'venv\b',
  'virtualenv\b',
  'uv\b',
```

`source .venv/bin/activate` is already covered by the baseline (`source\b`), as
is a `VENV=…` assignment. PYTHONPATH is sensitive and stays gated even when you
allow the commands above.
