;-- DROP TABLE users;
;-- DROP TABLE devices;
;-- DROP TABLE mappings;

-- "must_change" is 1 while the password was set by somebody else (the admin).
-- Databases created before the column existed get it from DatabaseService.
CREATE TABLE IF NOT EXISTS "users" (
    "user_id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "username" TEXT NOT NULL UNIQUE,
    "password" TEXT NOT NULL DEFAULT NULL,
    "is_admin" INTEGER NOT NULL DEFAULT 0,
    "must_change" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "mapping" (
    "user_id" INT NOT NULL,
    "device_id" INTEGER NOT NULL,
    PRIMARY KEY ("user_id", "device_id"),
    FOREIGN KEY ("user_id") REFERENCES users("user_id") ON DELETE CASCADE,
    FOREIGN KEY ("device_id") REFERENCES devices("device_id") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "devices" (
    "device_id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "devicename" TEXT NOT NULL,
    "device_address" TEXT,
    "mac" TEXT,
    "created_at" INTEGER DEFAULT CURRENT_TIMESTAMP
);

-- The one-time admin bootstrap: a row here means it has been used.
CREATE TABLE IF NOT EXISTS "bootstrap" (
    "id" INTEGER NOT NULL PRIMARY KEY CHECK ("id" = 1),
    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Only the SHA-256 of a token is stored, never the token itself.
CREATE TABLE IF NOT EXISTS "refresh_tokens" (
    "token_hash" TEXT NOT NULL PRIMARY KEY,
    "user_id" INTEGER NOT NULL,
    "expires_at" INTEGER NOT NULL,
    FOREIGN KEY ("user_id") REFERENCES users("user_id") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "reset_tokens" (
    "token_hash" TEXT NOT NULL PRIMARY KEY,
    "user_id" INTEGER NOT NULL UNIQUE,
    "expires_at" INTEGER NOT NULL,
    FOREIGN KEY ("user_id") REFERENCES users("user_id") ON DELETE CASCADE
);

-- Profile pictures. Separate tables, so the device and user lists never carry
-- image bytes. "version" changes with every upload and lets browsers cache.
CREATE TABLE IF NOT EXISTS "device_pictures" (
    "device_id" INTEGER NOT NULL PRIMARY KEY,
    "media_type" TEXT NOT NULL,
    "data" BLOB NOT NULL,
    "version" INTEGER NOT NULL,
    FOREIGN KEY ("device_id") REFERENCES devices("device_id") ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "user_pictures" (
    "user_id" INTEGER NOT NULL PRIMARY KEY,
    "media_type" TEXT NOT NULL,
    "data" BLOB NOT NULL,
    "version" INTEGER NOT NULL,
    FOREIGN KEY ("user_id") REFERENCES users("user_id") ON DELETE CASCADE
);
