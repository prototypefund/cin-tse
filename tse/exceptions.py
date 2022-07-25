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


class TSEOpenError(TSEError):
    """Raised if TSE cannot be opened."""


class TSETimeoutError(TSEError):
    """Raised if a TSE timeout occurs."""


class TSETimeNotSetError(TSEError):
    """Raised if the TSE time is not set."""


class TSEAlreadyInitializedError(TSEError):
    """Raised if a TSE are already initialized."""


class TSESelfTestError(TSEError):
    """Raised ff an error occurs during the self test.."""


class TSENeedsSelfTestError(TSEError):
    """Raised if a TSE needs a self test."""


class TSELoginError(TSEError):
    """Raised if a TSE user could not be logged in."""


class TSELogoutError(TSEError):
    """Raised if a TSE user could not be logged out."""


class TSEUnauthenticatedUserError(TSEError):
    """Raise if TSE user is not authenticated."""


class TSEClientNotExistError(TSEError):
    """Raise if the TSE client does not exist."""


class TSEPinBlockedError(TSEError):
    """Raised if a TSE login PIN was blocked."""


class TSESecretError(TSEError):
    """Raised if the secret is no correct."""


class TSEInternalError(TSEError):
    """Raised if the an internal TSE error occurs."""


class TSEDecommissionedError(TSEError):
    """Raised if the TSE is decommissioned."""


class TSECertificateExpiredError(TSEError):
    """Raised if the TSE certificate is expired."""


class TSEPukStateError(TSEError):
    """Raised if the change PUK is required."""


class TSEPinStateError(TSEError):
    """Raised if the change PIN is required."""
