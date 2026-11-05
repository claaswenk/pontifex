;-- DROP TABLE users;
;-- DROP TABLE devices;
;-- DROP TABLE mappings;

CREATE TABLE IF NOT EXISTS "users" (
    "user_id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "username" TEXT NOT NULL,
    "password" TEXT NOT NULL DEFAULT NULL,
    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS "mapping" (
    "user_id" INT NOT NULL ,
    "device_id" INTEGER NOT NULL,
    FOREIGN KEY ("user_id") REFERENCES users("user_id")
);

CREATE TABLE IF NOT EXISTS "devices" (
    "device_id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "devicename" TEXT NOT NULL,
    "device_address" TEXT,
    "created_at" INTEGER DEFAULT CURRENT_TIMESTAMP
);
