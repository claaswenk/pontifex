"""Backend container logger."""

from shared.logger import BaseLogger


class BackendLogger(BaseLogger):
    CONTAINER_ID = "backend"
