All calls below use `-k` because the containers create their own self-signed certificate.
Replace `<>` with your value. Authentication is always `Authorization: Bearer <token>`.

Errors are generic on purpose: `401` for every failed login, `404` for a device that is not yours,
`503` when the database or the wake relay is unavailable.

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

Response: `{"refresh_token": "...", "access_token": "...", "expires_in": 300, "role": "admin"}`

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

Response: `{"username": "anna", "role": "user", "token_expires_at": 1760000000}`

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

`409` if the name is taken.

10. Set a new password for a user (ends all their sessions; not for yourself, use step 7)
```
curl -k -X PUT https://localhost:7337/api/users/<username> \
  -H "Authorization: Bearer <admin token>" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "<>"
  }'
```

11. Delete a user (with their devices and sessions; not yourself, not the admin account: `409`)
```
curl -k -X DELETE https://localhost:7337/api/users/<username> \
  -H "Authorization: Bearer <admin token>"
```

---

## Devices (every user manages their own, the admin too)

A device of somebody else is reported exactly like one that does not exist (`404`).

12. List my devices
```
curl -k -X GET https://localhost:7337/api/devices \
  -H "Authorization: Bearer <>"
```

Response: `{"devices": [{"id": 1, "name": "ryzen", "address": "192.168.178.50", "mac": "a8:a1:59:29:3d:6d"}]}`

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

14. Delete a device
```
curl -k -X DELETE https://localhost:7337/api/devices/<id> \
  -H "Authorization: Bearer <>"
```

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

Response: `{"devices": [{"id": 1, "name": "nas", "address": "192.168.1.10", "status": "online", "latency_ms": 3.2}], "summary": {"total": 1, "online": 1, "offline": 0}}`

`status` is `online` or `offline`, so a UI can show a green or red dot. The device list comes from the database; addresses cannot be passed in the request. A device is online if one of TCP ports 22, 80, 443, 445 or 3389 answers (ICMP ping needs privileges the container does not have). Loopback, link-local and multicast targets are never probed.

---

## Other

18. Execute process (placeholder)
```
curl -k -X POST https://localhost:7337/api/process \
  -H "Authorization: Bearer <>"
```

## Not available yet

The database container is not part of the stack yet. Only call 1 works without it. Every other call needs it
(to check tokens, passwords or devices) and answers `503` until it exists.

## Removed

- `PUT /api/devices/wol` (free `ip` and `port` in the request): replaced by call 15.
- `POST /api/create-user/user` (replaced the admin): replaced by calls 8-11.
