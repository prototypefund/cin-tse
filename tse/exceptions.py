"""The exceptions module of the tse package."""


class ConnectionError(Exception):
    """Base exception for all connection errors."""


class ConnectionHostnameError(ConnectionError):
    """Raised if the Hostname is not correct."""


class ConnectionTimeoutError(ConnectionError):
    """Raised if a connection timeout occurs."""


class TSEError(Exception):
    """Base exception for all TSE error."""


class TSEInUseError(TSEError):
    """Raised if TSE is in use."""


class TSEIsBusy(TSEError):
    """Raised if TSE is busy."""


class TSEOpenError(TSEError):
    """Raised if TSE cannot be opened."""


class TSENotOpenError(TSEError):
    """Raised if TSE is not open."""


class TSETimeoutError(TSEError):
    """Raised if a TSE timeout occurs."""


class TSEDataError(TSEError):
    """Raised if TSEData are not correct."""
