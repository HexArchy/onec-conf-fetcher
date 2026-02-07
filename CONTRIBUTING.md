# Contributing

## Setup

```bash
git clone git@github.com:HexArchy/onec-conf-fetcher.git
cd onec-conf-fetcher
uv sync --dev
```

## Development

```bash
# Format
uv run ruff format src/

# Lint
uv run ruff check src/

# Type check
uv run mypy src/onec_conf_fetcher.py
```

## Submitting Changes

1. Fork the repo
2. Create a feature branch from `master`
3. Make your changes
4. Ensure all checks pass (`ruff format`, `ruff check`, `mypy`)
5. Open a PR against `master`

## Testing

Test against a live target or with sample 1C configuration files:

```bash
cp src/onec_conf_fetcher.py ~/.nxc/modules/
nxc smb <target> -u <user> -p <pass> -M onec_conf_fetcher -o EXPORT=true OUTPUT=/tmp/test
```

## Release Process

Releases are automated. Maintainers tag a version and the workflow publishes it:

```bash
git tag v0.2.0
git push origin v0.2.0
```
