# Logging

Backend, frontend and database each write their own request log. Code: [`src/shared/logger.py`](../src/shared/logger.py).

| Container | File | Volume |
|---|---|---|
| backend | `/app/logs/backend.log` | `backend_logs` |
| frontend | `/app/logs/frontend.log` | `frontend_logs` |
| database | `/app/logs/database.log` | `database_logs` |

`LOG_DIR` or `LOG_PATH` change the location. The file has mode `0600`, the directory `0700`. `wake-relay` has no log volume.

## What is logged

One line per request: caller, method, path, status and duration. Status 400 and above is a warning, 500 and above an error. An unhandled exception is logged with its stack trace.

```text
[user:anna] POST /api/devices status=201 duration=4.20ms
```

| Caller | Meaning |
|---|---|
| `peer:<container>` | another container, proven by its signature |
| `user:<name>` | signed-in user (token in the backend, session in the frontend) |
| `ip:<address>` | everybody else |
 The request line contains the path only. Query strings, request bodies and headers are not part of it.
- Control characters in logged text are escaped, so a request cannot forge a log line.
- Input that looks like an attack (SQL, path traversal, markup, template, shell) is reported by [`src/shared/input_validator.py`](../src/shared/input_validator.py) with the field name and the kind, never the value. It uses the standard Python `logging` module, not the log file above.

Read a log: `podman exec pontifex-backend cat /app/logs/backend.log`
