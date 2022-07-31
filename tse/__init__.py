"""The tse package."""
from typing import Protocol, List, Optional
from dataclasses import dataclass
from enum import Enum, auto
from datetime import datetime


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


class TSE(Protocol):
    def info(self) -> TSEInfo:
        ...

    def open(self) -> None:
        ...

    def close(self) -> None:
        ...

    def initialize(
            self, puk: str, admin_pin: str, time_admin_pin: str) -> None:
        ...

    def login_user(
            self, user_id: str, role: TSERole, pin: str) -> None:
        ...

    def logout_user(
            self, user_id: str, role: TSERole) -> None:
        ...

    def change_pin(self, role: TSERole, puk: str, new_pin: str) -> None:
        ...

    def register_user(self, user_id: str) -> None:
        ...

    def deregister_user(self, user_id: str) -> None:
        ...

    def user_list(self) -> List[str]:
        ...

    def run_self_test(self) -> None:
        ...

    def factory_reset(self) -> None:
        ...

    def update_time(self, user_id: str, time: datetime) -> None:
        ...

    def lock(self, state: bool) -> None:
        ...

    def disable_secure_element(self) -> None:
        ...

    def start_transaction(
            self, user_id: str, data: str, type: str) -> TSETransaction:
        ...

    def update_transaction(
            self, user_id: str, transaction: TSETransaction,
            data: str, type: str) -> None:
        ...

    def finish_transaction(
            self, user_id: str, transaction: TSETransaction,
            data: str, type: str) -> None:
        ...

    def started_transaction_list(self, user_id: str) -> List[int]:
        ...
