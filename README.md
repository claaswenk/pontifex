# pontifex

[![CI](https://github.com/claaswenk/pontifex/actions/workflows/ci.yml/badge.svg)](https://github.com/claaswenk/pontifex/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white)](Containerfile)
[![Container](https://img.shields.io/badge/container-podman-892CA0?logo=podman&logoColor=white)](Containerfile)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-FAB040?logo=pre-commit&logoColor=white)](.pre-commit-config.yaml)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot&logoColor=white)](.github/dependabot.yml)
[![Stars](https://img.shields.io/github/stars/claaswenk/pontifex?style=flat&logo=github)](https://github.com/claaswenk/pontifex/stargazers)

![Pontifex Owl](assets/pontifex_logo.png)

## Quick start (Linux, Podman)

```bash
git clone https://github.com/claaswenk/pontifex.git && cd pontifex
./scripts/init-env.sh        # creates .env with random secrets
podman compose up -d         # pulls the published images from GHCR
```

| Service | URL |
|---|---|
| Frontend | `https://127.0.0.1:8443` |
| Backend | `https://127.0.0.1:7337/api/health` |

- Both containers create their own self-signed certificate on first start (kept in named volumes). Your browser warns once.
- Both ports are bound to `127.0.0.1`. To reach them from other machines set `FRONTEND_BIND_ADDRESS` / `BACKEND_BIND_ADDRESS` in `.env` to a specific host IP, never `0.0.0.0`. For the frontend also set `TLS_EXTRA_SANS`, see [`.env.example`](.env.example).
- `./scripts/init-env.sh` prints `INITIAL_API_KEY`. It is needed once to create the first admin. The script never overwrites an existing `.env`.
- The database container is not part of the stack yet, so endpoints that need it answer with an error.

Pin a version instead of `latest` by setting `PONTIFEX_TAG=v1.0.0` (or `sha-<commit>`) in `.env`.

### Wake-on-LAN

A UDP broadcast from the container network never reaches your LAN. That is why the stack has a third container, `wake-relay`: it uses the host network, has no port, and only listens on a Unix socket shared with the backend. The backend sends it a MAC address and nothing else; the destination is fixed in `.env`.

1. Set `WOL_BROADCAST` in `.env` to the broadcast address of your LAN. It is the `brd` value in `ip -4 -br addr`, e.g. `192.168.178.255`. The default `255.255.255.255` works on many networks, the exact address is more reliable.
2. Start the stack: `podman compose up -d`. `podman ps` shows `pontifex-wake-relay` as healthy.
3. Prepare the device you want to wake: enable *Wake on LAN* / *Wake on PCIe* in its BIOS, switch off *ErP/EuP*, and make sure the operating system keeps it on, e.g. on Linux `sudo ethtool <nic> | grep Wake-on` must show `g` (on Fedora/Ubuntu: `nmcli connection modify "<connection>" 802-3-ethernet.wake-on-lan magic`). The device needs a cable; waking over Wi-Fi rarely works.

The relay is the only container in the host network. If you do not need Wake-on-LAN, remove the `wake-relay` service from `docker-compose.yml`.

### Build from the local sources

Use this before the images are published, or to test changes before a commit. The images are built with plain `podman build` (as in the CI) and tagged `local`, so compose starts them without pulling:

```bash
podman build -t ghcr.io/claaswenk/pontifex-backend:local  -f src/backend/Containerfile .
podman build -t ghcr.io/claaswenk/pontifex-frontend:local -f src/frontend/Containerfile .
PONTIFEX_TAG=local podman compose up -d
```

Windows PowerShell (dev system): run `.\scripts\init-env.ps1` instead of the `.sh`, and set the tag with `$env:PONTIFEX_TAG='local'` before `podman compose up -d`.

Reset including the generated certificates: `podman compose down -v`.

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
| `build` | Per service (backend, frontend): Podman build, SBOM (CycloneDX), Trivy HIGH/CRITICAL, non-root check, smoke test without a mounted certificate (as in a real deployment), healthcheck |
| `dast` | OWASP ZAP baseline against the backend. Manual run or `test/dast-**` branches only |
| `publish` | Push both images to GHCR from `main` or a `v*` tag, after `build` passes. Pushes the tested images without rebuilding. For tags it first checks the format (`v1.2.3`) and that the commit is on `main` |
| `release` | Only for `v*` tags, after `publish`: creates the GitHub Release with generated notes and the image digests. The only job with write access to repository contents |

Reports are uploaded as workflow artifacts: `sast-report`, `dependency-audit-report`, `sbom-<service>`, `container-image-<service>` and `dast-report`.

> [!WARNING]
> Put deliberately insecure code for DAST positive tests only on `test/dast-**` branches. It must never reach `main`.

Published images (tags: `sha-<commit>`, `v*` on version tags, `latest` on `main`):

```bash
podman pull ghcr.io/claaswenk/pontifex-backend:sha-<commit>
podman pull ghcr.io/claaswenk/pontifex-frontend:sha-<commit>
```

> [!TIP]
> Reference the image by digest (`@sha256:...`), which is printed in the `publish` job summary and in the release notes.

## Releases

Merging to `main` publishes `latest` and `sha-<commit>`. A **release** is a deliberate decision on top of that: you tag a commit on `main`, and the pipeline publishes the images under that version and creates the GitHub Release.

| Tag | Moves? | Use for |
|---|---|---|
| `latest` | yes, with every merge to `main` | test and home servers |
| `sha-<commit>` | no | reproducing one exact commit |
| `v1.2.3` | no, never | production and rollback |

Versions follow `vMAJOR.MINOR.PATCH`: `PATCH` for fixes, `MINOR` for new features that break nothing, `MAJOR` for changes that need action from the operator (for example new `.env` variables). Pre-releases use a suffix such as `v1.0.0-rc.1` and are marked as pre-release on GitHub. Start with `v0.1.0`.

### How to release

1. Merge `dev` into `main` with a pull request and wait until the CI on `main` is green.
2. Deploy `latest` somewhere and check that it starts (see [Quick start](#quick-start-linux-podman)).
3. Tag that commit on `main` and push the tag:

   ```bash
   git checkout main && git pull
   git tag -s v0.1.0 -m "v0.1.0"      # -s signs the tag; use -a if you have no signing key
   git push origin v0.1.0
   ```

4. Watch the run for the tag under **Actions**. It builds and scans both images again, checks the tag, publishes `pontifex-backend:v0.1.0` and `pontifex-frontend:v0.1.0`, and creates the release.
5. On the server set `PONTIFEX_TAG=v0.1.0` in `.env`, then:

   ```bash
   podman compose pull
   podman compose up -d
   ```

**Roll back:** set the previous tag in `.env` and run `podman compose up -d` again.

**Fix a bad release:** never move or delete a published tag, servers may already run it. Fix the problem on `dev`, merge to `main` and release the next patch version (`v0.1.1`).

> [!IMPORTANT]
> Push the tag only. Do not create the release by hand in the GitHub web UI: that creates the tag as a side effect and the pipeline then finds the release already present and leaves it unchanged, without the image digests in the notes.

If the pipeline rejects the tag (wrong format, or the commit is not on `main`), nothing is published. Delete the tag and tag again:

```bash
git push --delete origin v0.1.0
git tag -d v0.1.0
```

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=claaswenk/pontifex&type=Date)](https://star-history.com/#claaswenk/pontifex&Date)
