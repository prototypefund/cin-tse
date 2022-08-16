"""The tse package."""
from typing import Protocol, List, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum, auto
from datetime import datetime
from pathlib import Path


TimeRangeType = Optional[Tuple[datetime, datetime]]
TransactionRangeType = Union[int, Tuple[int, int], None]


class TSEState(Enum):
    """The state of the TSE."""

    INITIALIZED = auto()
    UNINITIALIZED = auto()
    DECOMMISSIONED = auto()


class TSERole(Enum):
    """The available TSE roles."""

    ADMIN = auto()
    TIME_ADMIN = auto()


@dataclass()
class TSEInfo:
    """The class to access TSE infomation."""

    public_key: str
    """
    Get the public key that belongs to the private key
    generating signatures.
    """

    model_name: str
    """Get TSE model name."""

    state: TSEState
    """Get initialization status of the TSE."""

    has_valid_time: bool
    """Has valid time is set in TSE."""

    certificate_id: str
    """Get certification ID as assigned by BSI."""

    certificate_expiration_date: datetime
    """Date after which the certificate of this TSE will be invalid. The
    TSE will not be usable afterwards, all data must have been
    exported before this date.
    """

    unique_id: str
    """Get an identifier guaranteed to be unambiguous for every TSE."""

    serial_number: str
    """
    A serial number is a hash value of a public key that belongs to a
    key pair.
    """

    signature_algorithm: str
    """The signature algorithm used by the TSE."""

    signature_counter: int
    """Amount of signatures that have been created with this TSE."""

    remaining_signatures: int
    """Remaining amount of signatures."""

    max_signatures: int
    """Remaining amount of signatures."""

    registered_users: int
    """The number of currently registered users."""

    max_registered_users: int
    """Maximum number of users that can be registered."""

    max_started_transactions: int
    """
    The maximal number of simultaneously opened transactions
    that can be managed by the TSE.
    """
    tar_export_size: int
    """Size of the whole TSE store in bytes, if exported."""

    needs_self_test: bool
    """The TSE needs a self test."""

    api_version: str
    """The TSE's software version"""


@dataclass()
class TSESignature:
    """The TSE signature representing class."""

    time: datetime
    """The date and time where the signature was created."""

    value: str
    """The value of the signature."""

    counter: int
    """The signature counter."""


@dataclass()
class TSETransaction:
    """This class represents a TSE transaction with all related properties."""

    number: int
    """The transaction number."""

    serial_number: str
    """The serial number of the TSE."""

    start_signature: Optional[TSESignature] = None
    """The start signature of the transaction."""

    update_signature: Optional[TSESignature] = None
    """The signature of ther last transaction update."""

    finish_signature: Optional[TSESignature] = None
    """The finish signature of the transaction."""


class TSEType(Protocol):
    """
    The TSE implementation for the Epson TSE.

    This class implements the TSE protocol defined in the tse module.
    To send data to the TSE, the respective TSE must
    be opened and then closed again. If the TSE is used exclusively by only
    one user, then this can also remain open. Opening and closing before
    and after writing is only necessary if several users share a TSE.
    If the TSE is currently being used by another user, then a TSEInUseError
    is raised.

    .. code:: python

        tse = TSE(<tse_id>, <hostname>)

        tse.open()
        # some operation
        tse.close()
    """

    def info(self) -> TSEInfo:
        """
        Get a :class:`tse.TSEInfo` object.

        The TSEInfo object provides information about the TSE and its state.

        **Role: None**

        Raises:
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def open(self) -> None:
        """
        Open the TSE for operations.

        **Role: None**

        Raises:
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE could not be opened.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def close(self) -> None:
        """
        Close the TSE device.

        **Role: None**

        Raises:
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE could not be opened.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def initialize(
            self,
            puk: str,
            admin_pin: str,
            time_admin_pin: str
            ) -> None:
        """
        Initialize the TSE device.

        Before the TSE can be used, it must be initialized. During the
        initialization the PUK, the PIN for the TSERole.TIME_ADMIN and the PIN
        for the TSERole.ADMIN are set.
        The length of the PUK is exactly 6 characters and the length
        for PINs is exactly 5 characters.

        **Role: None**

        Args:
            puk: The PUK of the TSE device.
            admin_pin: The Pin of the TSERole.ADMIN.
            time_admin_pin: The PIN of the TSERole.TIME_ADMIN.

        Raise:
            ValueError: If the lenght of PUK or PIN is not correct.
            tse.exceptions.TSECertificateExpiredError: If the certificate of
                the TSE is expired.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEAlreadyInitializedError: If TSE was already
                initialized.
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def login_user(
            self,
            user_id: str,
            role: TSERole,
            pin: str,
            ) -> None:
        """
        Login a user with specific role.

        A user can be any previously created user or the TSE user
        *Administrator*. Roles are used to restrict the calling
        of certain properties and
        methods. There are two possible roles TSERole.ADMIN and
        TSERole.TIME_ADMIN. The role needed to call a method is
        described in the documentation of the method.

        .. note::
            The TSERole.ADMIN will be logged out automatically after 15
            minutes. The TimeAdmin will be logged out after 8 hours.

        **Role: None**

        Args:
            user_id: The user ID. For Admin role only the "Administrator" user
                is allowed. For TimeAdmin all user IDs are allowed.
            role: A TSERole.
            pin: The PIN for the role.

        Raises:
            tse.exceptions.TSELoginError: If a login error occurs.
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.TSEPinBlockedError: If the PIN was blocked.
            tse.exceptions.TSESecretError: If the secret for authentication
                was wrong.
            tse.exceptions.TSEPukStateError: If the PUK change required. Maybe
                the TSE is not initialized.
            tse.exceptions.TSEPinStateError: If the PIN change required. Maybe
                the TSE is not initialized.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def logout_user(
            self,
            user_id: str,
            role: TSERole,
            ) -> None:
        """
        Logout a user with specific role.

        **Role: None**

        Args:
            user_id: The user ID. For Admin role only the *Administrator* user
                is allowed. For TimeAdmin all user IDs are allowed.
            role: A TSERole.

        Raises:
            tse.exceptions.TSELogoutError: If user is not logged in with
                the given role or the TSE is decommissioned.
            tse.exceptions.TSECertificateExpiredError: if the certificate of
                the TSE is expired. Either the validity of the certificate has
                expired or the TSE was decommissioned.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def change_pin(self, role: TSERole, puk: str, new_pin: str) -> None:
        """
        Set or unblock the PIN of a Role.

        This method can be used to reset the PIN of a role. If the PIN has
        been blocked, it will be unblocked again with the new PIN.
        The PIN/PUK authentication can fail up to 3 times, afterwards the
        PUK/PIN will be blocked automatically. If PUK is blocked, it cannot
        be recovered. The only way to recover is to replace.

        **Role: None**

        Args:
            role: A TSERole.
            puk: The PUK.
            new_pin: The new PIN for the role.

        Raises:
            tse.exceptions.TSELoginError: If a login error occurs.
            tse.exceptions.TSEPinBlockedError: If the PIN was blocked.

            tse.exceptions.TSEPinError: If the new PIN is not different from
                the old one or the given PIN was longer or shorter than 5
                characters.
            tse.exceptions.TSEAuthenticationError: If the PUK is blocked or the
                given PUK was wrong.
            tse.exceptions.TSESecretError: If the secret for authentication
                was wrong.
            tse.exceptions.TSEPukStateError: If the PUK change required. Maybe
                the TSE is not initialized.
            tse.exceptions.TSEPinStateError: If the PIN change required. Maybe
                the TSE is not initialized.
            tse.exceptions.TSECertificateExpiredError: if the certificate of
                the TSE is expired. Either the validity of the certificate has
                expired or the TSE was decommissioned.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def register_user(self, user_id: str) -> None:
        """
        Register user ID to be used in the TSE.

        The maximum length of the ID is 30 characters.

        **Role: TSERole.ADMIN**

        Args:
            user_id: The ID of the user (maximum length: 30 characters)

        Raises:
            ValueError: If maximum length of user ID is greater than
                30 characters.
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSEInternalError: The internal TSE error occures if
                the TSE is decommissioned or if an internal error occures.
                If the TSE is not decommissioned, the TSE host must be
                restarted.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def deregister_user(self, user_id: str) -> None:
        """
        Deregisters a user.

        The maximum length of the ID is 30 characters. IDs including "EPSON"
        are reserved by the TSE host, deleting by the user is prohibited.

        **Role: TSERole.ADMIN**

        Args:
            user_id: The ID of the user (maximum length: 30 characters)

        Raises:
            ValueError: If maximum length of user ID is greater than
                30 characters.
            tse.exceptions.TSEClientNotExistError: If the user does
                not exist.
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSEInternalError: The internal TSE error occures if
                the TSE is decommissioned or if an internal error occures.
                If the TSE is not decommissioned, the TSE host must be
                restarted.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def user_list(self) -> List[str]:
        """
        List all IDs of registered users.

        Although the user ID "EPSONXXXXXXXX" is included. It is
        an internal user ID and not a Point of Sale.

        **Role: TSERole.ADMIN**

        Raises:
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSEInternalError: The internal TSE error occures if
                the TSE is decommissioned or if an internal error occures.
                If the TSE is not decommissioned, the TSE host must be
                restarted.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def run_self_test(self) -> None:
        """
        Run self test for TSE device.

        After 25 hours, the self-test must be performed again.

        **Role: None**

        Raises:
            tse.exceptions.TSENotInitializedError: If the TSE is not
                initialized.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def register_secret(self, secret: str) -> None:
        """
        Set a new secret for authentication.

        **Role: TSERole.ADMIN**

        Args:
            secret: The shared secret for authentication.

        Raises:
            ValueError: If secret has not exactly 8 characters.
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSEInternalError: If an internal TSE error occurred.
                Normally, the TSE host must be restarted.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def update_time(self, user_id: str, time: datetime) -> None:
        """
        Update the TSE time.

        Date and time specified from POS to synchronize TSE and POS date
        and time.

        **Role: TSERole.TIME_ADMIN, TSERole.ADMIN**

        Args:
            user_id: The user who wants to set the time. This can be a
                registered user or the Administrator user. The user must
                be logged in with at least the TSERole.TIME_ADMIN role.
            time: The time as datetime type.

        Raises:
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.TIME_ADMIN.
            tse.exceptions.TSEInternalError: If an internal TSE error occurred.
                Normally, the TSE host must be restarted.
            tse.exceptions.TSECertificateExpiredError: If the certificate of
                the TSE is expired.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def lock(self, state: bool) -> None:
        """
        Lock the TSE.

        Transactions and export functions are not available when TSE is locked.
        Only functions belonging to User Authentication can be used.

        **Role: TSERole.ADMIN**

        Args:
            state: The lock state as boolean.

        Raises:
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSEInternalError: The internal TSE error occures if
                the TSE is decommissioned or if an internal error occures.
                If the TSE is not decommissioned, the TSE host must be
                restarted.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def disable_secure_element(self) -> None:
        """
        Take the TSE out of operation.

        .. warning::
            This method disables the Secure Element in a way that none of its
            functionality can be used anymore.

        **Role: TSERole.ADMIN**

        Raises:
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSEInternalError: If an internal TSE error occurred.
                Normally, the TSE host must be restarted.
            tse.exceptions.TSETimeNotSetError: If the TSE time is not set.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def start_transaction(
            self,
            user_id: str,
            data: str,
            type: str) -> TSETransaction:
        """
        Start a new transaction.

        **Role: TSERole.TIME_ADMIN**

        Args:
            user_id: The ID of the user who uses the TSE.
            data: The data to be written to the TSE.
            type: The type of the data.

        Raises:
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSECertificateExpiredError: If the certificate of
                the TSE is expired.
            tse.exceptions.TSETimeNotSetError: If the TSE time is not set.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def update_transaction(
            self,
            user_id: str,
            transaction: TSETransaction,
            data: str,
            type: str) -> None:
        """
        Update the transaction.

        This method updates the transaction and adds the update signature to
        the passed transaction object.

        **Role: TSERole.TIME_ADMIN**

        Args:
            user_id: The ID of the user who uses the TSE.
            transaction: The transaction object.
            data: The data to be written to the TSE.
            type: The type of the data.

        Raises:
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSECertificateExpiredError: If the certificate of
                the TSE is expired.
            tse.exceptions.TSETimeNotSetError: If the TSE time is not set.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def finish_transaction(
            self,
            user_id: str,
            transaction: TSETransaction,
            data: str,
            type: str) -> None:
        """
        Finish the transaction.

        This method finishes the transaction and adds the finish signature to
        the passed transaction object.

        **Role: TSERole.TIME_ADMIN**

        Args:
            user_id: The ID of the user who uses the TSE.
            transaction: The transaction object.
            data: The data to be written to the TSE.
            type: The type of the data.

        Raises:
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSECertificateExpiredError: If the certificate of
                the TSE is expired.
            tse.exceptions.TSETimeNotSetError: If the TSE time is not set.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def started_transaction_list(self, user_id: str) -> List[int]:
        """
        Get a list of unfinished transaction.

        When an empty string "" is specified, a list of transaction numbers
        of all incomplete transactions is returned regardless of the
        user ID.

        **Role: None**

        Args:
            user_id: The ID of the user who uses the TSE.

        Raises:
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """

    def export(
            self,
            filename: Path,
            user_id: str,
            transaction: TransactionRangeType = None,
            time: TimeRangeType = None,
            delete_data: bool = False) -> None:
        """
        Export the TSE logs.

        This method exports the application data, system messages, audit
        logs, and log data stored in the TSE in a standardized file format.
        The exported files are stored in a TAR archive.
        The data is exported for the respective user and can be optionally
        deleted from the TSE after the export.
        It is possible to export only certain records. The records can be
        filtered by transaction numbers or time ranges, but for the filtered
        export only one filter, either transaction or time, may be passed,
        otherwise the *TSEArgumentError* will be raised.

        .. note::
            If filtered data is exported, then it cannot be deleted.

        The following sample code exports all logs of a user and deletes
        the data from the TSE after export.

        .. code:: python

            tse = TSE(<tse_id>, <ip_address>)
            tse.open()
            tse.login_user('Administrator', TSERole.ADMIN, <admin_pin>)
            tse.export(Path(<path_to_file>), <user_id>)
            tse.close()

        **Role: TSERole.ADMIN**

        Args:
            filename: The filename including the path to the file where
                the data will be saved.
            user_id: The ID of the user whose logs should be exported.
            transaction: The transaction ID or a range of transaction IDs.
                The range for transactions must be passed as a tuple with two
                integers. The first one is the start transaction and the
                second is the end transaction. If only one transaction should
                be filtered, then the transaction ID must be passed as integer.
            time: The time range as tuple of datetime. First item is the start
                time and the second one is the end time.

        Raises:
            FileNotFoundError: If the given path does not exist.
            tse.exceptions.TSEArgumentError: If transaction and time
                filter passed.
            tse.exceptions.TSEArgumentTypeError: If the type of an
                argument is wrong
            tse.exceptions.TSENoUserError: If the user_id string is
                empty or None.
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSETimeNotSetError: If the time is not set.
            tse.exceptions.TSECertificateExpiredError: if the certificate of
                the TSE is expired.
            tse.exceptions.TSENeedsSelfTestError: If TSE needs a self test.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSETimeoutError: If TSE timeout error occurred.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """
