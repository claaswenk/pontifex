1. Health Check
```
curl -k -X GET https://localhost:13110/api/health
```

---

2. Create admin
```
curl -k -X POST https://localhost:13110/api/create-user/admin \
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
curl -k -X POST https://localhost:13110/api/create-user/user \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <>" \
  -d '{
    "username": "<>",
    "password": "<>"
  }'
```

---

4. Create device
```
curl -k -X POST https://localhost:13110/api/create-device \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <>" \
  -d '{
    "device_name": "<>",
    "address": "<>"
  }'
```

---

5. Connect user with device
```
curl -k -X POST https://localhost:13110/api/create-connection \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <>" \
  -d '{
    "username": "<>",
    "device_name": "<>"
  }'
```
---

6. Delete user
```
curl -k -X POST https://localhost:13110/api/delete/user \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <>" \
  -d '{
    "username": "<>"
  }'
```
---

7. Delete device
```
curl -k -X POST https://localhost:13110/api/delete/device \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <>" \
  -d '{
    "username": "<>"
  }'
```
---

8. Delete connection
```
curl -k -X POST https://localhost:13110/api/delete/connection \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <>" \
  -d '{
    "username": "<>",
    "device_name": "<>"
  }'
```
