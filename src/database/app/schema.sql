;-- DROP TABLE users;
;-- DROP TABLE devices;
;-- DROP TABLE mappings;

CREATE TABLE IF NOT EXISTS "users" (
    "user_id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "username" TEXT NOT NULL UNIQUE,
    "password" TEXT NOT NULL DEFAULT NULL,
    "is_admin" INTEGER NOT NULL DEFAULT 0,
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
    "created_at" INTEGER DEFAULT CURRENT_TIMESTAMP
);
