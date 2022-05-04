"""The module for the Epson backend."""


class TSE():
    """The TSE protocol implementation for the Epson TSE."""

    def __init__(self, host: str, ssl: bool = False) -> None:
        """Initialize the TSE instance."""
        self._host = host
        self._ssl = ssl
