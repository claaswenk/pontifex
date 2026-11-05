from sqlite3 import Connection

import hashlib
import logging
import sqlite3
import os

class DB_Interface():
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.db_path = os.environ.get("DB_PATH")

        self.__connection = self.__connect()
        self.__cursor = self.__connection.cursor()
        self.__schema_path = "schema.sql"
        self.__salt_length = 16

    def __connect(self) -> Connection:
        self.logger.log("Trying to connect to DB")

        if not os.path.exists(self.db_path):
            self.logger.warning(f"No database file found under {self.db_path}")
            self.logger.warning(f"Creating it myself")

        con = sqlite3.connect(self.db_path)
        return con

    def __gen_salt(self) -> bytes:
        return os.urandom(self.__salt_length)

    def __hash_password_initial(self, password: str) -> str:
        salt = self.__gen_salt()
        hash = hashlib.sha256(salt + password.encode(encoding='utf-8')).digest()
        to_return = salt.hex() + hash.hex()
        return to_return

    def __verify_password(self, password_input: str, password_db: str) -> bool:
        salt = password_db[:self.__salt_length]
        password_db_hash = password_db[self.__salt_length:]

        password_input_hash = hashlib.sha256(salt, password_input.encode(encoding='utf-8')).digest()
        if password_db_hash == password_input_hash:
            return True
        return False

    def initialize_db(self):
        self.__cursor.executescript(self.__schema_path)

    def create_user(self, username, password):
        self.__cursor.execute("INSERT INTO users (username, password) VALUES(?, ?)", username, password)
