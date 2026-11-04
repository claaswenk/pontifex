from sqlite3 import Connection

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

    def __connect(self) -> Connection:
        self.logger.log("Trying to connect to DB")

        if not os.path.exists(self.db_path):
            self.logger.warning(f"No database file found under {self.db_path}")
            self.logger.warning(f"Creating it myself")

        con = sqlite3.connect(self.db_path)
        return con

    def initialize_db(self):
        self.__cursor.executescript(self.__schema_path)

    def sanitize_input(self):
        pass

    def select(self):
        pass

    def delete(self):
        pass

    def update(self):
        pass

    def insert(self):
        pass
