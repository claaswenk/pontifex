# pontifex

[![CI](https://github.com/claaswenk/pontifex/actions/workflows/ci.yml/badge.svg)](https://github.com/claaswenk/pontifex/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white)](requirements.in)
[![Container](https://img.shields.io/badge/container-podman-892CA0?logo=podman&logoColor=white)](docker-compose.yml)
[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-FAB040?logo=pre-commit&logoColor=white)](.pre-commit-config.yaml)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-025E8C?logo=dependabot&logoColor=white)](.github/dependabot.yml)
[![Stars](https://img.shields.io/github/stars/claaswenk/pontifex?style=flat&logo=github)](https://github.com/claaswenk/pontifex/stargazers)

<p align="center">
  <img src="assets/pontifex_logo_small.png" alt="Pontifex Owl" width="260">
</p>

## Quick start (Linux, Podman)

```bash
git clone https://github.com/claaswenk/pontifex.git && cd pontifex
./scripts/init-env.sh        # creates .env with random secrets and prints INITIAL_API_KEY
podman compose up -d         # pulls the published images from GHCR
podman compose ps            # backend, frontend and wake-relay become "healthy"
```

Then open `https://127.0.0.1:8443`, accept the certificate warning once and follow "First start? Create the administrator" on the login page. The setup key is the `INITIAL_API_KEY` from `.env`; it works once. After that sign in and add your first device (name, address and MAC address).

Further users are added by the administrator on the **Users** page. The administrator chooses the first password, so a new user has to replace it at the first sign-in before anything else is open. The same happens after the administrator sets a new password for a user.

| Service | URL |
|---|---|
| Frontend | `https://127.0.0.1:8443` |
| Backend (REST API, see [`docs/api.md`](docs/api.md)) | `https://127.0.0.1:7337/api/health` |

- Every container creates its own self-signed certificate on first start (kept in named volumes).
- The database container has no published port. Only the backend reaches it, over the compose network.
- Both published ports are bound to `127.0.0.1`. To reach the frontend from another machine, see [Access from other machines](#access-from-other-machines).
- `./scripts/init-env.sh` never overwrites an existing `.env`. If the ports 8443 or 7337 are taken, set `FRONTEND_PORT` and `PORT` in `.env`.

What the UI does: the device list shows state, latency and MAC address and refreshes by itself every 10 seconds. Devices can be edited, woken and given a round picture; the account page sets a profile picture. A wrong input keeps everything typed and marks only the refused field.

### Access from other machines

Only the frontend is meant to be reached from outside. Keep the backend on `127.0.0.1`.

1. In `.env` set `FRONTEND_BIND_ADDRESS` to the IP of the host in your LAN (never `0.0.0.0`) and `TLS_EXTRA_SANS` to the name or IP you will type in the browser, e.g. `TLS_EXTRA_SANS=IP:192.168.178.20,DNS:pontifex.local`.
2. The certificate is created on the first start only. If the stack already ran, recreate it: `podman compose down -v`, then `podman compose up -d`. This also deletes the database.
3. Open the port in the host firewall, e.g. `sudo firewall-cmd --add-port=8443/tcp --permanent && sudo firewall-cmd --reload`.
4. Browse to `https://<host-ip>:8443` and accept the certificate warning once.

The traffic is encrypted, but the self-signed certificate is not trusted by browsers. Do not expose the port to the internet; put a reverse proxy with a real certificate in front of it if you need that.

Pin a version instead of `latest` by setting `PONTIFEX_TAG=v1.0.0` (or `sha-<commit>`) in `.env`.

### Wake-on-LAN

A UDP broadcast from the container network never reaches your LAN. That is why the stack has a third container, `wake-relay`: it uses the host network, has no port, and only listens on a Unix socket shared with the backend. The backend sends it a MAC address and nothing else; the destination is fixed in `.env`.

1. Set `WOL_BROADCAST` in `.env` to the broadcast address of your LAN. It is the `brd` value in `ip -4 -br addr`, e.g. `192.168.178.255`. The default `255.255.255.255` works on many networks, the exact address is more reliable.
2. Start the stack: `podman compose up -d`. `podman ps` shows `pontifex-wake-relay` as healthy.
3. Prepare the device you want to wake: enable *Wake on LAN* / *Wake on PCIe* in its BIOS, switch off *ErP/EuP*, and make sure the operating system keeps it on, e.g. on Linux `sudo ethtool <nic> | grep Wake-on` must show `g` (on Fedora/Ubuntu: `nmcli connection modify "<connection>" 802-3-ethernet.wake-on-lan magic`). The device needs a cable; waking over Wi-Fi rarely works.

The relay is the only container in the host network. If you do not need Wake-on-LAN, remove the `wake-relay` service from `docker-compose.yml`.

**Nothing happens although the UI says "Magic packet sent"?** The message only means that the packet was handed to the network. Check in this order: the device wakes with a tool on the host (`wakeonlan <mac>`, `ether-wake`); `WOL_BROADCAST` is the broadcast address of the LAN the device is in; the host is wired to that LAN. A Podman machine behind NAT (Windows/WSL2, macOS) never forwards the broadcast to the LAN; run the stack on a Linux host in the LAN.

### Build from the local sources

Use this before the images are published, or to test changes before a commit. The images are built with plain `podman build` (as in the CI) and tagged `local`, so compose starts them without pulling:

```bash
podman build -t ghcr.io/claaswenk/pontifex-backend:local  -f src/backend/Containerfile .
podman build -t ghcr.io/claaswenk/pontifex-frontend:local -f src/frontend/Containerfile .
podman build -t ghcr.io/claaswenk/pontifex-database:local -f src/database/Containerfile .
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

Run the same checks manually, and the tests (they need the packages of `requirements.txt` in a Python 3.11 environment):

```bash
pre-commit run --all-files
uvx pip-audit -r requirements.txt --no-deps --disable-pip
python -m unittest discover -s tests -t .
```

## Input validation

Every value that comes from outside goes through [`src/shared/input_validator.py`](src/shared/input_validator.py) first, in all three containers, and only the returned value is used afterwards: JSON bodies, form fields, URL segments, cookies and tokens.

- **Allow-lists, not block-lists.** A value is accepted only if it has the expected type, length and characters (for example a username is `[a-z0-9][a-z0-9._-]{2,63}`). Anything else is refused with the rule of the field, so the answer does not depend on what the attacker sent.
- **Bounded first.** Length is checked before any pattern runs, and the patterns have no nested quantifiers, so a long input cannot stall a request.
- **Text only.** NUL bytes and strings that cannot be encoded as UTF-8 are refused everywhere. Names also refuse control, line-break and bidi characters.
- **Prepared statements only.** The database container passes values as `?` parameters; `tests/test_input_validator.py` fails if a query is built from a string.
- **Attack attempts are logged**, with the field name and the kind (`sql`, `path traversal`, `markup`, `template`, `shell`, `control characters`), never the value. Passwords are never inspected: they may contain any character.
- **The frontend refuses over-long input instead of cutting it**, because a cut name can turn into a different valid one. The backend still validates everything again; the frontend is not trusted by it.

Add a new input in three steps: add a rule to `InputValidator`, call it where the value is read, and add the hostile cases to `tests/test_input_validator.py`.

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
| `build` | Per service (backend, frontend, database): Podman build, SBOM (CycloneDX), Trivy HIGH/CRITICAL, non-root check, smoke test without a mounted certificate (as in a real deployment), healthcheck. Not run for version tags |
| `dast` | OWASP ZAP baseline against the backend. Manual run or `test/dast-**` branches only |
| `publish` | Only on `main`, after `build` passes: pushes the tested images to GHCR as `sha-<commit>` and `latest`, without rebuilding |
| `promote` | Only for `v*` tags: checks the format (`v1.2.3`) and that the commit is on `main`, then adds the version tag to the `sha-<commit>` image that `main` already published. Nothing is rebuilt, so the version has the same digest as that image |
| `release` | Only for `v*` tags, after `promote`: creates the GitHub Release with generated notes and the image digests. The only job with write access to repository contents |

Reports are uploaded as workflow artifacts: `sast-report`, `dependency-audit-report`, `sbom-<service>`, `container-image-<service>` and `dast-report`.

> [!WARNING]
> Put deliberately insecure code for DAST positive tests only on `test/dast-**` branches. It must never reach `main`.

Published images (tags: `sha-<commit>`, `v*` on version tags, `latest` on `main`):

```bash
podman pull ghcr.io/claaswenk/pontifex-backend:sha-<commit>
podman pull ghcr.io/claaswenk/pontifex-frontend:sha-<commit>
podman pull ghcr.io/claaswenk/pontifex-database:sha-<commit>
```

> [!TIP]
> Reference the image by digest (`@sha256:...`), which is printed in the `publish` job summary and in the release notes.

## Releases

Merging to `main` builds the images once and publishes `latest` and `sha-<commit>`. A **release** is a deliberate decision on top of that: you tag a commit on `main`, and the pipeline gives the already published image of that commit the version tag and creates the GitHub Release.

| Tag | Moves? | Use for |
|---|---|---|
| `latest` | yes, with every merge to `main` | test and home servers |
| `sha-<commit>` | no | reproducing one exact commit |
| `v1.2.3` | no, never | production and rollback |

Versions follow `vMAJOR.MINOR.PATCH`: `PATCH` for fixes, `MINOR` for new features that break nothing, `MAJOR` for changes that need action from the operator (for example new `.env` variables). Pre-releases use a suffix such as `v1.0.0-rc.1` and are marked as pre-release on GitHub. Start with `v0.1.0`.

### How to release

1. Merge `dev` into `main` with a pull request and wait until the CI on `main` is green, including `publish`. The tag run needs the `sha-<commit>` image from that run and fails without it.
2. Deploy `latest` somewhere and check that it starts (see [Quick start](#quick-start-linux-podman)).
3. Tag that commit on `main` and push the tag:

   ```bash
   git checkout main && git pull
   git tag -s v0.1.0 -m "v0.1.0"      # -s signs the tag; use -a if you have no signing key
   git push origin v0.1.0
   ```

4. Watch the run for the tag under **Actions**. It checks the tag, adds `v0.1.0` to `pontifex-backend`, `pontifex-frontend` and `pontifex-database`, and creates the release. It takes seconds because nothing is rebuilt. A version tag that already exists with another digest is refused.
5. On the server set `PONTIFEX_TAG=v0.1.0` in `.env`, then:

   ```bash
   podman compose pull
   podman compose up -d
   ```

**Roll back:** set the previous tag in `.env` and run `podman compose up -d` again.

**Fix a bad release:** never move or delete a published tag, servers may already run it. Fix the problem on `dev`, merge to `main` and release the next patch version (`v0.1.1`).

> [!IMPORTANT]
> Push the tag only. Do not create the release by hand in the GitHub web UI: that creates the tag as a side effect and the pipeline then finds the release already present and leaves it unchanged, without the image digests in the notes.

If the pipeline rejects the tag (wrong format, the commit is not on `main`, or no `sha-<commit>` image exists yet), nothing is published. Delete the tag and tag again:

```bash
git push --delete origin v0.1.0
git tag -d v0.1.0
```

## Star history

[![Star History Chart](https://api.star-history.com/svg?repos=claaswenk/pontifex&type=Date)](https://star-history.com/#claaswenk/pontifex&Date)
