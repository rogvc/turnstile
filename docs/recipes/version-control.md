# Version control

Copy into the `allow` array of your `config.toml`. Deny rules still take
precedence, so pair these with deny patterns for anything you don't want (e.g.
`'git\s+push\b'` to block pushes).

```toml
  # Version control
  'git\b',
  'gh\b',
```

`GH_TOKEN=… gh …` needs no entry: the assignment prefix is stripped before `gh`
is matched.
