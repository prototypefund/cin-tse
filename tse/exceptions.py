"""The exceptions module of the tse package."""


class ConnectError(Exception):
    """Raised if a connection error occurs."""

    pass


class TSEError(Exception):
    """Base error for all TSE error."""

    pass


class TSENotFoundError(TSEError):
    """Raise if the TSE is not available."""

    pass


class TSEInUseError(TSEError):
    """Raised if TSE is in use."""

    pass
