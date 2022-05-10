"""The exceptions module of the tse package."""


class ConnectError(Exception):
    """Base exception for all connection errors."""


class NotConnectedError(ConnectError):
    """Raised if there is no connection to TSE host."""


class ConnectionClosedError(ConnectError):
    """Raised if the connection to TSE host was closed."""


class ConnectionTimeoutError(ConnectError):
    """Raised if a connection timeout occurs."""


class TSEError(Exception):
    """Base exception for all TSE error."""


class TSENotFoundError(TSEError):
    """Raise if the TSE is not available."""


class TSEInUseError(TSEError):
    """Raised if TSE is in use."""


class TSEIsBusy(TSEError):
    """Raised if TSE is busy."""


class TSEOpenError(TSEError):
    """Raised if TSE cannot be opened."""


class TSENotOpenError(TSEError):
    """Raised if TSE is not open."""


class TSETimeoutError(ConnectError):
    """Raised if a TSE timeout occurs."""
