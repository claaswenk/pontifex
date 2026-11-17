All calls below use `-k` because the containers create their own self-signed certificate.
Replace `<>` with your value. Authentication is always `Authorization: Bearer <token>`.

Errors are generic on purpose: `401` for every failed login, `404` for a device that is not yours,
`503` when the database or the wake relay is unavailable.
Every input is validated first (see `src/shared/input_validator.py`). A refused value answers `400` with the
rule of the field, except where a different answer is safer: `401` for a malformed login or token, `403` for an
unusable current password, `404` for a malformed username or id in the URL. Request bodies must be JSON objects.

---

## Health

1. Health check (public)
```
curl -k -X GET https://localhost:7337/api/health
```

---

## First start and sign-in

2. Create the admin (once; the key is `INITIAL_API_KEY` from `.env`, after that the call answers `410`)
```
curl -k -X POST https://localhost:7337/api/create-user/admin \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <INITIAL_API_KEY>" \
  -d '{
    "username": "<>",
    "password": "<>"
  }'
```

Usernames: 3-64 characters, lower case letters, digits, `.`, `_`, `-` (upper case is converted to lower case).
Passwords: 12-1024 characters.

3. Log in
```
curl -k -X POST https://localhost:7337/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "<>",
    "password": "<>"
  }'
```

Response: `{"refresh_token": "...", "access_token": "...", "expires_in": 300, "role": "admin", "must_change_password": false}`

`must_change_password` is `true` for a user whose password the admin chose (steps 9 and 10). See step 7.

Wrong password and unknown user both answer `401 {"error": "Invalid username or password."}`.
After 5 failed attempts for one user from one address, or 30 from one address, the answer is `429` with a
`Retry-After` header (seconds), also for the correct password. The counters reset after 15 minutes.

4. Get a new access token (access tokens live 5 minutes)
```
curl -k -X POST https://localhost:7337/api/token \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<>"
  }'
```

5. Log out (revokes the refresh token; an unknown token is ignored)
```
curl -k -X POST https://localhost:7337/api/logout \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<>"
  }'
```

6. Who am I
```
curl -k -X GET https://localhost:7337/api/me \
  -H "Authorization: Bearer <>"
```

Response: `{"username": "anna", "role": "user", "token_expires_at": 1760000000, "picture": null, "must_change_password": false}`. `picture` is the version of the profile picture, `null` without one (see 14b).

7. Change my own password (admin and user; returns a fresh token pair, all other sessions end)
```
curl -k -X PUT https://localhost:7337/api/me/password \
  -H "Authorization: Bearer <>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "<>",
    "new_password": "<>"
  }'
```

A wrong current password answers `403`. Wrong guesses count against the same limit as the login (`429`).

A user whose password the admin chose (a new user, or after step 10) has to replace it first. Until then the account can only
call steps 3 to 7. Every other call answers
`403 {"error": "Password change required.", "code": "password_change_required"}`. The new password must differ from the
temporary one (`400`, `"field": "new_password"`). The admin account, and a user who set the password through a reset token (step 10b), are never asked.

---

## User management (admin only)

There is exactly one admin, created in step 2. Everybody else is a regular user.

8. List users (never contains password hashes)
```
curl -k -X GET https://localhost:7337/api/users \
  -H "Authorization: Bearer <admin token>"
```

9. Add a user
```
curl -k -X POST https://localhost:7337/api/users \
  -H "Authorization: Bearer <admin token>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "<>",
    "password": "<>"
  }'
```

`409` if the name is taken. The user has to choose their own password at the first sign-in (step 7).

10. Set a new password for a user (ends all their sessions and asks them to replace it at the next sign-in; not for yourself, use step 7)
```
curl -k -X PUT https://localhost:7337/api/users/<username> \
  -H "Authorization: Bearer <admin token>" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "<>"
  }'
```

10a. Forgot password, step 1 (admin): issue a one-time reset token for a user and hand it to them over a trusted channel
```
curl -k -X POST https://localhost:7337/api/users/<username>/reset-token \
  -H "Authorization: Bearer <admin token>"
```

Response `201`: `{"username": "<>", "reset_token": "<>", "expires_in": 900}`. The token is shown only once, is valid for 15 minutes
and works once. A new token replaces an earlier one. The admin uses step 7 for their own password (`409`).

10b. Forgot password, step 2 (the user, no login needed): set a new password with the token
```
curl -k -X POST https://localhost:7337/api/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "reset_token": "<>",
    "new_password": "<>"
  }'
```

Response `200`: `{"status": "ok"}`. All sessions of the user end; they log in again with the new password.
`401` for an unknown, used or expired token, `400` for an invalid password (the token stays valid).
Wrong tokens count per address: after 5 failures `429` (15 minutes). Changing the password, renaming or deleting the user also voids a pending token.

11. Delete a user (with their devices and sessions; not yourself, not the admin account: `409`)
```
curl -k -X DELETE https://localhost:7337/api/users/<username> \
  -H "Authorization: Bearer <admin token>"
```

11b. Change my username (needs the current password; ends all my sessions and returns a fresh token pair; the role can never be changed: `403`)
```
curl -k -X PATCH https://localhost:7337/api/me \
  -H "Authorization: Bearer <>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "<>",
    "current_password": "<>"
  }'
```

Response: `{"username": "<new name>", "role": "user", "refresh_token": "...", "access_token": "...", "expires_in": 300}`

- `409` if the name is taken or is already yours, `400` for an invalid name or any field other than `username` and `current_password`.
- `403` if the password is wrong (counts against the login limit, `429` when exceeded) or if `role` is sent.
- Devices, password and role stay with the account.

11a. Delete my own account (with my devices and sessions; needs the current password; the admin account cannot be deleted: `409`)
```
curl -k -X DELETE https://localhost:7337/api/me \
  -H "Authorization: Bearer <>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "<>"
  }'
```

`403` if the password is wrong (counts against the login limit, `429` when exceeded). Afterwards the admin can create the user again with step 9.

---

## Devices (every user manages their own, the admin too)

A device of somebody else is reported exactly like one that does not exist (`404`).

12. List my devices
```
curl -k -X GET https://localhost:7337/api/devices \
  -H "Authorization: Bearer <>"
```

Response: `{"devices": [{"id": 1, "name": "ryzen", "address": "192.168.178.50", "mac": "a8:a1:59:29:3d:6d", "picture": null}]}`. `picture` is the version of the device picture, `null` without one.

13. Add a device
```
curl -k -X POST https://localhost:7337/api/devices \
  -H "Authorization: Bearer <>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ryzen",
    "address": "192.168.178.50",
    "mac": "A8:A1:59:29:3D:6D"
  }'
```

- `name`: 1-64 characters, unique per user (`409` otherwise). At most 100 devices per user.
- `address`: host name or IP. Loopback, link-local, multicast and unspecified addresses are refused.
- `mac`: six hex pairs with `:`, `-`, `.` or without separators; stored as `aa:bb:cc:dd:ee:ff`. Broadcast, all-zero and multicast MACs are refused.
- `image` (optional): a picture, see 14b.
- A refused value answers with the name of the field: `{"error": "...", "field": "mac"}` (`409` for a taken name: `"field": "name"`).

13a. Get one device
```
curl -k -X GET https://localhost:7337/api/devices/<id> \
  -H "Authorization: Bearer <>"
```

13b. Edit a device (name, address and MAC, all three are sent; the picture stays)
```
curl -k -X PUT https://localhost:7337/api/devices/<id> \
  -H "Authorization: Bearer <>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ryzen",
    "address": "192.168.178.51",
    "mac": "A8:A1:59:29:3D:6D"
  }'
```

The same rules as in 13. `409` if the user has another device of that name (keeping the own name is fine).

14. Delete a device
```
curl -k -X DELETE https://localhost:7337/api/devices/<id> \
  -H "Authorization: Bearer <>"
```

14a. Device picture: set, get, remove
```
curl -k -X PUT https://localhost:7337/api/devices/<id>/picture \
  -H "Authorization: Bearer <>" \
  -H "Content-Type: application/json" \
  -d '{"image": "<base64>"}'
curl -k -X GET    https://localhost:7337/api/devices/<id>/picture -H "Authorization: Bearer <>"
curl -k -X DELETE https://localhost:7337/api/devices/<id>/picture -H "Authorization: Bearer <>"
```

`GET` answers `{"media_type": "image/png", "image": "<base64>", "version": 3}`, `PUT` answers `{"id": 1, "picture": 4}`. The version changes with
every new picture, so a browser can cache by it. `404` if there is no picture or the device is not yours.

14b. Profile picture: the same three calls on `/api/me/picture` (`PUT` answers `{"picture": 4}`, `DELETE` answers `{"status": "ok"}`).

A picture is PNG, JPEG or WebP, at most 200 KB, sent as base64 text. The type is detected from the bytes, never taken from the sender; SVG and
everything else is refused with `400`.

15. Wake a device (Wake-on-LAN)
```
curl -k -X POST https://localhost:7337/api/devices/<id>/wake \
  -H "Authorization: Bearer <>"
```

Response: `{"id": 1, "status": "sent"}`

`sent` means: the magic packet was handed to the network. There is no way to know whether the device woke up;
check with the metrics call below. The request carries no MAC, address or port: the MAC comes from the stored
device, and the destination (`WOL_BROADCAST`, `WOL_PORT`) is configured in the `wake-relay` container.
`503` if the relay is not running.

---

## Monitoring

16. System (CPU, RAM, disk, load of the host running the backend)
```
curl -k -X GET https://localhost:7337/api/monitoring \
  -H "Authorization: Bearer <>"
```

Response: `{"status": "ok", "service": "pontifex-backend", "stats": {"cpu": {...}, "memory": {...}, "disk": {...}, "load_average": {...}, "host_uptime_seconds": 0, "service_uptime_seconds": 0}}`

CPU, memory, load and host uptime describe the host. `disk` describes the filesystem at `MONITOR_DISK_PATH` (default `/`) inside the container.

17. Metrics (online/offline state of your own devices)
```
curl -k -X GET https://localhost:7337/api/metrics \
  -H "Authorization: Bearer <>"
```

Response: `{"devices": [{"id": 1, "name": "nas", "address": "192.168.1.10", "mac": "aa:bb:cc:dd:ee:01", "status": "online", "latency_ms": 3.2, "picture": null}], "summary": {"total": 1, "online": 1, "offline": 0}}`

`status` is `online` or `offline`, so a UI can show a green or red dot. The device list comes from the database; addresses cannot be passed in the request. A device is online if one of TCP ports 22, 80, 443, 445 or 3389 answers (ICMP ping needs privileges the container does not have). Loopback, link-local and multicast targets are never probed.

---

## Removed

- `PUT /api/devices/wol` (free `ip` and `port` in the request): replaced by call 15.
- `POST /api/create-user/user` (replaced the admin): replaced by calls 8-11.
- `POST /api/process` (placeholder without function).
