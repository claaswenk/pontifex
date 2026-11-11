"""Exceptions that cross the container boundary (raised by one side, handled by the other)."""


class BootstrapConsumedError(Exception):
    """The one-time admin bootstrap has already been used."""
