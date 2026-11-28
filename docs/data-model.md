# Data model

SQLite, owned by the database container (`DB_PATH`, volume `sqlite_data`). Schema: [`schema.sql`](../src/database/app/schema.sql).

```mermaid
erDiagram
    users ||--o{ mapping : owns
    devices ||--|| mapping : "belongs to"
    users ||--o{ refresh_tokens : has
    users ||--o| reset_tokens : has
    users ||--o| user_pictures : has
    devices ||--o| device_pictures : has
    users {
        int user_id PK
        text username
        text password
        int is_admin
        int must_change
    }
    devices {
        int device_id PK
        text devicename
        text device_address
        text mac
    }
    mapping {
        int user_id PK
        int device_id PK
    }
    refresh_tokens {
        text token_hash PK
        int user_id
        int expires_at
    }
    reset_tokens {
        text token_hash PK
        int user_id
        int expires_at
    }
    device_pictures {
        int device_id PK
        text media_type
        blob data
        int version
    }
    user_pictures {
        int user_id PK
        text media_type
        blob data
        int version
    }
```

- `password` holds an Argon2id hash. Tokens are stored as SHA-256 hashes only.
- `must_change` is 1 while the password was chosen by the administrator.
- A device has one owner. The database service creates the device and its `mapping` row together.
- Pictures are in separate tables, so lists never carry image bytes. `version` changes with every upload.
- Deleting a user also deletes their devices, pictures and tokens.
- The table `bootstrap` has at most one row. It marks that the administrator was created, so the setup can run only once.
