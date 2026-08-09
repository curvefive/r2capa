# Contributing

Use Python 3.10 or newer and keep changes focused. Install the development environment and hooks:

```sh
make bootstrap
.venv/bin/pre-commit install
make check
```

Add a regression fixture for every extractor change. Prefer structured r2 JSON fields over parsing
rendered assembly. New feature mappings should document their capa feature, r2 source fields, and
address semantics in the pull request.

Commit messages should be imperative and pull requests should explain behavior changes, tests, and
known backend differences.
