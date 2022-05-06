"""The exceptions module of the tse package."""


class ConnectError(Exception):
    """Base exception for all connection errors."""

    pass


class NotConnectedError(ConnectError):
    """Raised if there is no connection to TSE host."""

    pass


class TSEError(Exception):
    """Base exception for all TSE error."""

    pass


class TSENotFoundError(TSEError):
    """Raise if the TSE is not available."""

    pass


class TSEInUseError(TSEError):
    """Raised if TSE is in use."""

    pass


class TSEOpenError(TSEError):
    """Raised if TSE is in use."""

    pass
