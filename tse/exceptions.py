"""The exceptions module of the tse package."""


class ConnectError(Exception):
    """Base exception for all connection errors."""


class NotConnectedError(ConnectError):
    """Raised if there is no connection to TSE host."""


class ConnectionClosedError(ConnectError):
    """Raised if the connection to TSE host was closed."""


class TimeoutError(ConnectError):
    """Raised if timeout occurs."""


class TSEError(Exception):
    """Base exception for all TSE error."""


class TSENotFoundError(TSEError):
    """Raise if the TSE is not available."""


class TSEInUseError(TSEError):
    """Raised if TSE is in use."""


class TSEOpenError(TSEError):
    """Raised if TSE cannot be opened."""


class TSENotOpenError(TSEError):
    """Raised if TSE is not open."""
