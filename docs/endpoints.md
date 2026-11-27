# Endpoints

Request and response examples for the backend: [API examples](api.md).

Access: **public** = no token, **signed in** = any valid access token, **admin** = administrator token, **setup key** = `INITIAL_API_KEY`, **container** = signed request of another container.

## Backend (`https://<host>:7337/api`)

| Method | Path | Access | Purpose |
|---|---|---|---|
| GET | `/health` | public | Health check |
| GET | `/internal/ping` | container (frontend, database) | Peer check |
| POST | `/create-user/admin` | setup key | Create the administrator, once (`410` afterwards) |
| POST | `/login` | public | Username and password to tokens |
| POST | `/token` | public | Refresh token to new access token |
| POST | `/logout` | public | Revoke a refresh token |
| POST | `/reset-password` | public | New password with a reset token |
| GET | `/me` | signed in | Own account |
| PUT | `/me/password` | signed in | Change own password |
| PATCH | `/me` | signed in | Change own username |
| DELETE | `/me` | signed in | Delete own account |
| GET, PUT, DELETE | `/me/picture` | signed in | Own profile picture |
| GET, POST | `/users` | admin | List users, add a user |
| PUT | `/users/<username>` | admin | Set a user's password |
| DELETE | `/users/<username>` | admin | Delete a user |
| POST | `/users/<username>/reset-token` | admin | Issue a reset token |
| GET, POST | `/devices` | signed in | List own devices, add a device |
| GET, PUT, DELETE | `/devices/<id>` | signed in | One own device |
| GET, PUT, DELETE | `/devices/<id>/picture` | signed in | Device picture |
| POST | `/devices/<id>/wake` | signed in | Wake a device |
| GET | `/metrics` | signed in | Online state and latency of own devices |
| GET | `/monitoring` | signed in | CPU, memory, disk and load of the host |

While the password is temporary, only `/me`, `/me/password`, `/login`, `/token` and `/logout` are open.

## Frontend (`https://<host>:8443`)

| Path | Method | Access | Purpose |
|---|---|---|---|
| `/` | GET | any | Redirect to `/devices` |
| `/setup` | GET, POST | public | Create the administrator |
| `/login` | GET, POST | public | Sign in |
| `/logout` | POST | signed in | Sign out |
| `/devices` | GET, POST | signed in | Device list, add a device |
| `/devices/live` | GET | signed in | Status as JSON for the refresh |
| `/devices/<id>/edit` | GET, POST | signed in | Edit a device |
| `/devices/<id>/wake` | POST | signed in | Wake |
| `/devices/<id>/delete` | POST | signed in | Delete |
| `/devices/<id>/picture` | GET | signed in | Picture |
| `/devices/<id>/picture/delete` | POST | signed in | Remove the picture |
| `/users` | GET, POST | admin | User list, add a user |
| `/users/<name>/password` | POST | admin | Set a password |
| `/users/<name>/delete` | POST | admin | Delete a user |
| `/account` | GET | signed in | Profile and password |
| `/account/new-password` | GET | signed in | Page for a temporary password |
| `/account/password` | POST | signed in | Change the password |
| `/account/picture` | GET, POST | signed in | Profile picture |
| `/account/picture/delete` | POST | signed in | Remove the profile picture |
| `/health` | GET | public | Health check |
| `/internal/ping` | GET | container (backend) | Peer check |

## Database (internal, `/api`)

Only the backend may call these, except `/health`. They are not a public interface.

| Group | Paths |
|---|---|
| Health | `/health`, `/internal/ping` |
| Setup | `/bootstrap` |
| Accounts | `/accounts`, `/accounts/lookup`, `/accounts/<username>`, `/accounts/password`, `/accounts/rename`, `/accounts/<username>/picture`, `/accounts/<username>/picture/version` |
| Tokens | `/tokens`, `/tokens/lookup`, `/tokens/revoke`, `/reset-tokens`, `/reset-tokens/use` |
| Devices | `/owners/<username>/devices`, `/owners/<username>/devices/<id>`, `/owners/<username>/devices/<id>/picture` |
