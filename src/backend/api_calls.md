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
