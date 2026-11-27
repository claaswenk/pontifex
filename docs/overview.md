# Overview

Pontifex is a self-hosted web application to see which of your devices are online and to wake them with Wake-on-LAN. It runs as containers (Podman or Docker Compose).

## Functions

| Function | Description |
|---|---|
| Device list | Every user keeps their own devices: name, address (host name or IP) and MAC address. At most 100 per user. |
| Status | A device is online if one of the TCP ports 22, 80, 443, 445 or 3389 answers. The list shows state and latency and refreshes every 10 seconds. |
| Wake-on-LAN | Sends a magic packet for the stored MAC address of a device. |
| Pictures | Optional picture per device and per profile (PNG, JPEG or WebP, at most 200 KB). |
| Accounts | Sign-in with username and password, password change, forgotten-password handling by the administrator. |
| REST API | The same functions as JSON API, independent of the web UI. See [API examples](api.md). |

## Roles

There is exactly one administrator. Everybody else is a regular user.

| | Administrator | User |
|---|---|---|
| Own devices: add, edit, delete, wake, status | yes | yes |
| Own password and profile picture | yes | yes |
| Add users, set their password, delete them | yes | no |
| See the devices of other users | no | no |

The administrator is created once on the setup page with the `INITIAL_API_KEY` from `.env`.

## More

- [Architecture](architecture.md)
- [User guide](guide-user.md) and [administrator guide](guide-admin.md)
- [Endpoints](endpoints.md)
