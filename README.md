# pontifex

[![CI](https://github.com/claaswenk/pontifex/actions/workflows/ci.yml/badge.svg)](https://github.com/claaswenk/pontifex/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white)](Containerfile)
[![Container](https://img.shields.io/badge/container-podman-892CA0?logo=podman&logoColor=white)](Containerfile)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-FAB040?logo=pre-commit&logoColor=white)](.pre-commit-config.yaml)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot&logoColor=white)](.github/dependabot.yml)
[![Stars](https://img.shields.io/github/stars/claaswenk/pontifex?style=flat&logo=github)](https://github.com/claaswenk/pontifex/stargazers)

## Quick start

```bash
podman build --format docker -t pontifex -f Containerfile .
podman run --rm -p 127.0.0.1:8080:8080 pontifex
curl http://127.0.0.1:8080/
```

> [!IMPORTANT]
> Build with `--format docker`. The default OCI format drops the `HEALTHCHECK` instruction.

## Developer setup

Run once after cloning:

```bash
pip install pre-commit      # or: brew install pre-commit
pre-commit install
```

Before each commit, the hooks run Gitleaks, Hadolint, Bandit and basic file checks. Hook versions are pinned to commit SHAs.

Run the same checks manually:

```bash
pre-commit run --all-files
uvx pip-audit -r requirements.txt --no-deps --disable-pip
```

## Dependencies

`requirements.in` holds the direct dependencies. `requirements.txt` is generated from it and contains pinned versions with hashes. Never edit it by hand.

```bash
uv pip compile requirements.in --generate-hashes --python-version 3.11 --universal -o requirements.txt
```

The image installs with `--require-hashes`, so a changed or tampered package fails the build. Dependabot opens weekly PRs for pip, GitHub Actions and the base-image digest. After merging a pip update, re-run the command above.

## CI pipeline

Defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). Every gate below fails the pipeline.

| Job | Checks |
|---|---|
| `secrets-and-lint` | Gitleaks over the full history, Hadolint |
| `sast` | Bandit, severity MEDIUM or higher |
| `dependency-audit` | `pip-audit`, any known vulnerability |
| `build` | Podman build, SBOM (CycloneDX), Trivy HIGH/CRITICAL, non-root check, smoke test, healthcheck |
| `dast` | OWASP ZAP baseline. Manual run or `test/dast-**` branches only |
| `publish` | Push to GHCR from `main` or a `v*` tag, after `build` passes. Pushes the tested image without rebuilding |

Reports are uploaded as workflow artifacts: `sast-report`, `dependency-audit-report`, `sbom`, `container-image` and `dast-report`.

> [!WARNING]
> Put deliberately insecure code for DAST positive tests only on `test/dast-**` branches. It must never reach `main`.

Published image:

```bash
podman pull ghcr.io/claaswenk/pontifex:sha-<commit>
```

> [!TIP]
> Reference the image by digest (`@sha256:...`), which is printed in the `publish` job summary.

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=claaswenk/pontifex&type=Date)](https://star-history.com/#claaswenk/pontifex&Date)
