"""The exceptions module of the tse package."""


class ConnectError(Exception):
    """Raised if a connection error occurs."""

    pass


class TSEError(Exception):
    """Base error for all TSE error."""

    pass
