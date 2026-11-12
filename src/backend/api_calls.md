1. Health Check
```
curl -k -X GET https://localhost:7337/api/health
```

---

2. Create admin
```
curl -k -X POST https://localhost:7337/api/create-user/admin \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <>" \
  -d '{
    "username": "<>",
    "password": "<>"
  }'
```

---

3. Create user
```
curl -k -X POST https://localhost:7337/api/create-user/user \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <>" \
  -d '{
    "username": "<>",
    "password": "<>"
  }'
```

---

4. Request access token
```
curl -k -X POST https://localhost:7337/api/token \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "<>"
  }'
```

---

5. Execute process
```
curl -k -X POST https://localhost:7337/api/process \
  -H "Authorization: Bearer <>"
```

---

6. Wake-on-LAN
```
curl -k -X PUT https://localhost:7337/api/devices/wol \
  -H "Content-Type: application/json" \
  -d '{
    "mac": "AA:BB:CC:DD:EE:FF",
    "ip": "255.255.255.255",
    "port": 9
  }'
```

---

7. Monitoring (CPU, RAM, disk, load of the host running the backend)
```
curl -k -X GET https://localhost:7337/api/monitoring \
  -H "Authorization: Bearer <>"
```

Response: `{"status": "ok", "service": "pontifex-backend", "stats": {"cpu": {...}, "memory": {...}, "disk": {...}, "load_average": {...}, "host_uptime_seconds": 0, "service_uptime_seconds": 0}}`

CPU, memory, load and host uptime describe the host. `disk` describes the filesystem at `MONITOR_DISK_PATH` (default `/`) inside the container.

---

8. Metrics (online/offline state of your own devices)
```
curl -k -X GET https://localhost:7337/api/metrics \
  -H "Authorization: Bearer <>"
```

Response: `{"devices": [{"name": "nas", "address": "192.168.1.10", "status": "online", "latency_ms": 3.2}], "summary": {"total": 1, "online": 1, "offline": 0}}`

`status` is `online` or `offline`, so a UI can show a green or red dot. The device list comes from the database; addresses cannot be passed in the request. A device is online if one of TCP ports 22, 80, 443, 445 or 3389 answers (ICMP ping needs privileges the container does not have). Loopback, link-local and multicast targets are never probed. Needs the database container (like every token-protected endpoint): without it the backend cannot validate tokens or list devices.
