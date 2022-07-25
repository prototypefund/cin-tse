"""
The module for the Epson backend.

In this module the TSE protocol for Epson devices and helpers are implemented.
"""
import socket
import json
from datetime import datetime
from hashlib import sha256
from base64 import b64encode
from datetime import datetime
from xml.etree import ElementTree
from typing import Optional
from tse import exceptions as tse_ex
from tse import TSEInfo, TSEState, TSERole


def _hash(challenge: str, secret: str) -> bytes:
    """
    Hash the challenge and secret composition.

    This function hashes the given data using the following formula:
    encodeBase64(sha256(challenge + secret))

    Args:
        challenge: The challenge returned by the TSE.
        secret: The shared secret.
    """
    composition = challenge+secret

    return b64encode(sha256(composition.encode()).digest())


class _TSEHost:
    """
    This class offers the possibility to communicate with an Epson TSE host.

    The ePOS Device XML interface is used for communication. Any device
    that provides this interface can be addressed (e.g. the Epson TSE
    server or Epson TSE printer).

    During the initialization of the instance, a socket connection to the
    TSE host is established. To send data to the TSE, the respective TSE must
    be opened and then closed again. If the TSE is used exclusively by only
    one client, then this can also remain open. Opening and closing before
    and after writing is only necessary if several clients share a TSE.

    .. code:: python

        tse_host = _TSEHost(<hostname>)

        tse_host.tse_open(<tse_id>)
        tse_host.tse_send(<tse_id>, <data_dict>)
        tse_host.tse_close(<tse_id>)
    """

    def __init__(
            self, host: str, ssl: bool = False, timeout: int = 120) -> None:
        """
        Initialize the _TSEHost instance.

        This method establishes a TCP socket connection to host and sets
        the *client_id* and *protocol_version* properties.

        Args:
            host: The hostname or IP address of the host.
            ssl: If true, a SSL encrypted connection is used.
            timeout: The socket timeout in seconds.

        Raises:
            tse.exceptions.ConnectionError: If a unexpected error occurred.
            tse.exceptions.ConnectionTimeoutError: If socket timeout occurred.
            tse.exceptions.ConnectionHostnameError: If hostname format is not
                correct.
        """
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(timeout)

            if ssl:
                self._socket.connect((host, 8143))
            else:
                self._socket.connect((host, 8009))

            response = self._socket.recv(1024)

            root = ElementTree.fromstring(response.decode().rstrip('\x00'))
            client_id = root.find('*/client_id').text  # type: ignore
            protocol_version = root.find(
                    '*/protocol_version').text  # type: ignore
            self._client_id = client_id
            self._protocol_version = protocol_version

        except socket.gaierror:
            raise tse_ex.ConnectionHostnameError(
                f'The connection to the host "{host}" could not '
                'be established. The hostname has no valid format.'
            )

        except socket.timeout:
            raise tse_ex.ConnectionTimeoutError(
                f'The connection to the host "{host}" could not'
                'be established. A timeout error occurs.'
            )

        except Exception as ex:
            raise tse_ex.ConnectionError(
                f'The connection to the host "{host}" could not '
                f'be established ({str(ex)}).'
            )

    def __del__(self) -> None:
        """
        Cleanup the TSEHost instance.

        This method closes the connection to the TSE host.
        """
        try:
            self._socket.close()

        except AttributeError:
            pass

    @property
    def client_id(self) -> Optional[str]:
        """
        Get client-ID returnd for the host after connection.

        Returns:
            The client-ID as string or None if client is not connected.
        """
        return self._client_id

    @property
    def protocol_version(self) -> Optional[str]:
        """
        Get protocol version returnd for the host after connection.

        Returns:
            The protocol version as string or None if client is not connected.
        """
        return self._protocol_version

    def _send(self, xml: str) -> str:
        r"""
        Send ePOS device XML data to the Host.

        The method minifies the passed XML data and expands the string
        with the character *\\x00*. The host expect this character at the
        end of the sent data.

        Args:
            xml: The XML data as string.

        Returns:
            The XML response from the host as string without
            *\\x00* at the end.

        Raises:
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.

        """
        try:
            xml = xml+'\x00'
            xml = xml.replace('\n', '').replace(' ', '')
            self._socket.send(xml.encode())
            response = ''

            while True:
                response += self._socket.recv(1024).decode()

                if '\x00' in response:
                    break

            return response.rstrip('\x00')

        except socket.timeout:
            raise tse_ex.ConnectionTimeoutError(
                'The data could not be sent to the TSE host. '
                'Timeout error occurs.'
            )

        except (OSError, AttributeError):
            raise tse_ex.ConnectionError(
                'There is no established host connection. '
                'Please connect again.'
            )

    def tse_open(self, tse_id: str) -> None:
        """
        Open the TSE for operations.

        Args:
            tse_id: The ID of the TSE device.

        Raises:
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE could not be opened.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """
        xml = '''
            <open_device>
                <device_id>{}</device_id>
                <data>
                    <type>type_storage</type>
                </data>
            </open_device>
            '''.format(tse_id)

        root = ElementTree.fromstring(self._send(xml))
        code = root.find('./code').text  # type: ignore

        match code:
            case 'DEVICE_IN_USE':
                raise tse_ex.TSEInUseError(
                    f'The TSE {tse_id} is in use.'
                )
            case 'DEVICE_OPEN_ERROR' | 'DEVICE_NOT_FOUND':
                raise tse_ex.TSEOpenError(
                    'The TSE {tse_id} could not be opened.'
                )
            case 'OK':
                pass
            case _:
                raise tse_ex.TSEError(
                    f'An unexpected TSE error occurred: {code}.'
                )

    def tse_send(self, tse_id: str, data: dict, timeout: int = 3) -> dict:
        """
        Send data to the TSE JSON API.

        The data passed in the data dictionary is converted to the JSON
        format and sent to the TSE. The method returns the return value
        of the TSE.

        Args:
            tse_id: The ID of the TSE device.
            data: The data as dictionary.
            timeout: TSE operation timeout in seconds.

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
        xml = '''
            <device_data>
                <device_id>{}</device_id>
                <data>
                    <type>operate</type>
                    <timeout>{}</timeout>
                    <requestdata>{}</requestdata>
                </data>
            </device_data>"
            '''.format(tse_id, timeout*1000, json.dumps(data))

        root_element = ElementTree.fromstring(self._send(xml))
        code_element = root_element.find('.//code')
        result_element = root_element.find('./data/resultdata')

        if isinstance(code_element, ElementTree.Element):
            code = code_element.text

            match code:
                case 'ERROR_TIMEOUT':
                    raise tse_ex.TSETimeoutError(
                        'A timeout error occurred while sending data to '
                        'the TSE'
                    )
                case 'ERROR_DEVICE_BUSY':
                    raise tse_ex.TSEInUseError(
                        'The TSE is in use.'
                    )
                case 'DEVICE_NOT_OPEN':
                    raise tse_ex.TSEOpenError(
                        'The TSE device is not open.'
                    )
                case 'SUCCESS':
                    if isinstance(result_element, ElementTree.Element) \
                            and isinstance(result_element.text, str):
                        return json.loads(result_element.text)

                case _:
                    raise tse_ex.TSEError(
                        f'Unexpected TSE error occures: {code}.'
                    )

        return {}

    def tse_close(self, tse_id: str) -> None:
        """
        Close the TSE device.

        Args:
            tse_id: The ID of the TSE device.

        Raises:
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE in not open.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """
        xml = '''
            <close_device>
                <device_id>{}</device_id>
            </close_device>
            '''.format(tse_id)

        root = ElementTree.fromstring(self._send(xml))
        code = root.find('code').text  # type: ignore

        match code:
            case 'DEVICE_IN_USE':
                raise tse_ex.TSEInUseError(
                    'The TSE {tse_id} is in use.'
                )
            case 'DEVICE_NOT_OPEN':
                raise tse_ex.TSEOpenError(
                    'The TSE {tse_id} is not open.'
                )
            case 'OK':
                pass
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )


class TSE():
    """
    The TSE implementation for the Epson TSE.

    This class implements the TSE protocol defined in the tse module.
    To send data to the TSE, the respective TSE must
    be opened and then closed again. If the TSE is used exclusively by only
    one client, then this can also remain open. Opening and closing before
    and after writing is only necessary if several clients share a TSE.

    .. code:: python

        tse = TSE(<tse_id>, <hostname>)

        tse.open()
        # some operation
        tse.initialize('12345', '12345', '54321')
        tse.close()
    """

    def __init__(
            self,
            tse_id: str,
            host: str,
            secret: str = 'EPSONKEY',
            ssl: bool = False,
            timeout: int = 3
            ) -> None:
        """
        Initialize the TSE instance.

        During the initialization process, a connection to TSE host is
        established, which is used for communication afterwards.

        Args:
            tse_id: The ID of the TSE device.
            host: The hostname or IP address of the host.
            secret: The shared secret for authentication.
            ssl: If true, a SSL encrypted connection is used.
            timeout: Timeout for TSE operations in seconds.

        Raises:
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
            tse.exceptions.ConnectionTimeoutError: If socket timeout occurred.
            tse.exceptions.ConnectionHostnameError: If hostname format is not
                correct.
        """
        self._tse_host = _TSEHost(host, ssl, timeout=120)
        self._tse_id = tse_id
        self._timeout = timeout
        self._secret = secret

    @property
    def info(self) -> TSEInfo:
        """
        Get a bnn.TSEInfo object.

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
        data = {
            'storage': {
                'type': 'COMMON',
                'vendor': ''
            },
            'function': 'GetStorageInfo',
            'input': {},
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=self._timeout
        )

        code = result['result']

        match code:
            case 'EXECUTION_OK':
                pass
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

        tse_info = result['output']['tseInformation']
        state_data = tse_info['tseInitializationState']
        certificate_expiration_date = datetime.strptime(
            tse_info['certificateExpirationDate'], '%Y-%m-%dT%H:%M:%S%z'
        )
        needs_self_test = not tse_info['hasPassedSelfTest']
        api_version = str(tse_info['softwareVersion'])

        match state_data:
            case 'INITIALIZED':
                state = TSEState.INITIALIZED
            case 'UNINITIALIZED':
                state = TSEState.UNINITIALIZED
            case 'DECOMMISSIONED':
                state = TSEState.DECOMMISSIONED

        info = TSEInfo(
            public_key=tse_info['tsePublicKey'],
            model_name=tse_info['vendorType'],
            state=state,
            has_valid_time=tse_info['hasValidTime'],
            certificate_id=tse_info['tseDescription'],
            certificate_expiration_date=certificate_expiration_date,
            signature_algorithm=tse_info['signatureAlgorithm'],
            unique_id=tse_info['cdcId'],
            signature_counter=tse_info['createdSignatures'],
            remaining_signatures=tse_info['remainingSignatures'],
            max_signatures=tse_info['maxSignatures'],
            registered_clients=tse_info['registeredClients'],
            max_registered_clients=tse_info['maxRegisteredClients'],
            serial_number=tse_info['serialNumber'],
            max_started_transactions=tse_info['maxStartedTransactions'],
            tar_export_size=tse_info['tarExportSize'],
            needs_self_test=needs_self_test,
            api_version=api_version,
        )

        return info

    def _get_challenge(self) -> str:
        """
        Get challenge data.

        The data is used to calculate the hash value required
        for user authentication.

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
        data = {
            'storage': {
                'type': 'TSE',
                'vendor': 'TSE1'
            },
            'function': 'GetChallenge',
            'input': {
                'userId': 'Administrator'
            },
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'EXECUTION_OK':
                pass
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

        return result['output']['challenge']

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
        self._tse_host.tse_open(self._tse_id)

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
        self._tse_host.tse_close(self._tse_id)

    def initialize(
            self, puk: str,
            admin_pin: str,
            time_admin_pin: str
            ) -> None:
        """
        Initialize the TSE device.

        The maximum length of the PUK is 6 characters and the maximum length
        for PINs is 5 characters.

        **Role: None**

        Args:
            puk: The PUK of the TSE device.
            admin_pin: The Pin of the Admin role.
            time_admin_pin: The PIN of the Time Admin role.

        Raise:
            ValueError: If the PUK or PIN is too long.
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
        if len(puk) > 6:
            raise ValueError('The PUK is too long (maximum 6 character).')
        elif len(admin_pin) > 5:
            raise ValueError('The Admin PIN is to long (maximum 5 character)')
        elif len(time_admin_pin) > 5:
            raise ValueError(
                'The Time Admin PIN is to long (maximum 5 character)'
            )

        data = {
            'storage': {
                'type': 'TSE',
                'vendor': 'TSE1'
            },
            'function': 'SetUp',
            'input': {
                'puk': puk,
                'adminPin': admin_pin,
                'timeAdminPin': time_admin_pin
            },
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'OTHER_ERROR_TSE_ALREADY_SET_UP':
                raise tse_ex.TSEAlreadyInitializedError(
                    f'The TSE {self._tse_id} was already initialized.'
                )
            case 'TSE1_ERROR_WRONG_STATE_NEEDS_SELF_TEST':
                raise tse_ex.TSENeedsSelfTestError(
                    f'The TSE {self._tse_id} needs a self test.'
                )
            case 'EXECUTION_OK':
                return None
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def login_user(
            self,
            user_id: str,
            role: TSERole,
            pin: str,
            ) -> None:
        """
        Login a user with specific role.

        Roles are used to restrict the calling of certain properties and
        methods. There are two possible roles Admin and the TimeAdmin.
        The role needed to call a method is described in the documentation
        of the method.

        .. note::
            The TSERole.ADMIN will be logged out automatically after 15
            minutes. The TimeAdmin will be logged out after 8 hours.

        **Role: None**

        Args:
            user_id: The user ID. For Admin role only the "Administrator" user
                is allowed. For TimeAdmin all client IDs are allowed.
            role: A TSERole.
            pin: The PIN for the role.

        Raises:
            tse.exceptions.TSELoginError: If a login error occurs.
            tse.exceptions.TSEPinBlockedError: If the PIN was blocked.
            tse.exceptions.TSESecretError: If the secret for authentication
                was wrong.
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
        challenge = self._get_challenge()

        hash = _hash(challenge, self._secret)

        if role == TSERole.ADMIN:
            login_function = 'AuthenticateUserForAdmin'

            data = {
                'storage': {
                    'type': 'TSE',
                    'vendor': 'TSE1'
                },
                'function': login_function,
                'input': {
                    'userId': user_id,
                    'pin': pin,
                    'hash': hash.decode()
                },
                'compress': {
                    'required': False,
                    'type': ''
                }
            }
        else:
            login_function = 'AuthenticateUserForTimeAdmin'

            data = {
                'storage': {
                    'type': 'TSE',
                    'vendor': 'TSE1'
                },
                'function': login_function,
                'input': {
                    'clientId': user_id,
                    'pin': pin,
                    'hash': hash.decode()
                },
                'compress': {
                    'required': False,
                    'type': ''
                }
            }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'OTHER_ERROR_INVALID_ADMIN_USER_ID':
                raise tse_ex.TSELoginError(
                    'Only the "Administrator" user can be logged in '
                    'with TSERole.ADMIN role.'
                )
            case 'TSE1_ERROR_AUTHENTICATION_FAILED':
                remaining_retries = result['output']['remainingRetries']

                raise tse_ex.TSELoginError(
                        f'The user {user_id} could not login as {role} role '
                        f'(remaining retries: {remaining_retries}).'
                )
            case 'TSE1_ERROR_AUTHENTICATION_PIN_BLOCKED':
                raise tse_ex.TSEPinBlockedError(
                    f'The PIN for {role} was blocked.'
                )
            case 'OTHER_ERROR_HOST_AUTHENTICATION_FAILED':
                raise tse_ex.TSESecretError('Wrong authentication secret.')
            case 'EXECUTION_OK':
                return None
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def logout_user(
            self,
            user_id: str,
            role: TSERole,
            ) -> None:
        """
        Logout a user with specific role.

        **Role: None**

        Args:
            user_id: The user ID. For Admin role only the "Administrator" user
                is allowed. For TimeAdmin all client IDs are allowed.
            role: A TSERole.

        Raises:
            tse.exceptions.TSELogoutError: If user is not logged in with
                the given role.
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
        if role == TSERole.ADMIN:
            if user_id != 'Administrator':
                raise tse_ex.TSELogoutError(
                    'Only the "Administrator" user can be logged in '
                    'with TSERole.ADMIN role.'
                )

            data = {
                'storage': {
                    'type': 'TSE',
                    'vendor': 'TSE1'
                },
                'function': 'LogOutForAdmin',
                'input': {
                },
                'compress': {
                    'required': False,
                    'type': ''
                }
            }
        else:
            data = {
                'storage': {
                    'type': 'TSE',
                    'vendor': 'TSE1'
                },
                'function': 'LogOutForTimeAdmin',
                'input': {
                    'clientId': user_id,
                },
                'compress': {
                    'required': False,
                    'type': ''
                }
            }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER':
                raise tse_ex.TSELogoutError(
                    f'The user {user_id} not logged in with '
                    'TSERole.ADMIN role.'
                )
            case 'OTHER_ERROR_UNAUTHENTICATED_TIME_ADMIN_USER':
                raise tse_ex.TSELogoutError(
                    f'The user {user_id} not logged in with '
                    'TSERole.TIME_ADMIN role.'
                )
            case 'EXECUTION_OK':
                return None
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def register_client(self, client_id: str) -> None:
        """
        Registers client ID to be used in the TSE.

        The maximum length of the ID is 30 characters.

        **Role: TSERole.ADMIN**

        Args:
            client_id: The ID of the client (maximum length: 30 characters)

        Raises:
            ValueError: If maximum length of client ID is greater than
                30 characters.
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSEInternalError: If an internal TSE error occurred.
                Normally, the TSE host must be restarted.
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
        data = {
            'storage': {
                'type': 'TSE',
                'vendor': 'TSE1'
            },
            'function': 'RegisterClient',
            'input': {
                'clientId': client_id,
            },
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'TSE1_ERROR_NOT_AUTHORIZED':
                raise tse_ex.TSEInternalError(
                    'A internal TSE error occurred. Normally, '
                    'the TSE host must be restarted.')
            case 'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER':
                raise tse_ex.TSEUnauthenticatedUserError(
                    'No user logged in with TSERole.ADMIN role.'
                )
            case 'JSON_ERROR_INVALID_PARAMETER_RANGE':
                raise ValueError(
                    'Maximum length of client ID is 30 characters.'
                )
            case 'EXECUTION_OK':
                return None
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def deregister_client(self, client_id: str) -> None:
        """
        Deregisters a client.

        The maximum length of the ID is 30 characters. IDs including "EPSON"
        are reserved by the TSE host, deleting by the user is prohibited.

        **Role: TSERole.ADMIN**

        Args:
            client_id: The ID of the client (maximum length: 30 characters)

        Raises:
            ValueError: If maximum length of client ID is greater than
                30 characters.
            tse.exceptions.TSEClientNotExistError: If the client does
                not exist.
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSEInternalError: If an internal TSE error occurred.
                Normally, the TSE host must be restarted.
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
        data = {
            'storage': {
                'type': 'TSE',
                'vendor': 'TSE1'
            },
            'function': 'DeregisterClient',
            'input': {
                'clientId': client_id,
            },
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'TSE1_ERROR_NOT_AUTHORIZED':
                raise tse_ex.TSEInternalError(
                    'A internal TSE error occurred. Normally, '
                    'the TSE host must be restarted.')
            case 'TSE1_ERROR_CLIENT_NOT_REGISTERED':
                raise tse_ex.TSEClientNotExistError(
                    f'The client {client_id} does not exist.'
                )
            case 'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER':
                raise tse_ex.TSEUnauthenticatedUserError(
                    'No user logged in with TSERole.ADMIN role.'
                )
            case 'JSON_ERROR_INVALID_PARAMETER_RANGE':
                raise ValueError(
                    'Maximum length of client ID is 30 characters.'
                )
            case 'EXECUTION_OK':
                return None
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {result}.'
                )

    def client_list(self):
        """
        List all client IDs of registered clients.

        Although the client ID "EPSONXXXXXXXX" is included. It is
        an internal client ID and not a Point of Sale.

        **Role: TSERole.ADMIN**

        Raises:
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.ADMIN.
            tse.exceptions.TSEInternalError: If an internal TSE error occurred.
                Normally, the TSE host must be restarted.
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
        data = {
            'storage': {
                'type': 'TSE',
                'vendor': 'TSE1'
            },
            'function': 'GetRegisteredClientList',
            'input': {},
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'TSE1_ERROR_NOT_AUTHORIZED':
                raise tse_ex.TSEInternalError(
                    'A internal TSE error occurred. Normally, '
                    'the TSE host must be restarted.')
            case 'EXECUTION_OK':
                return result['output']['registeredClientIdList']
            case 'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER':
                raise tse_ex.TSEUnauthenticatedUserError(
                    'No user logged in with TSERole.ADMIN role.'
                )
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def run_self_test(self) -> None:
        """
        Run self test for TSE device.

        **Role: None**

        Raises:
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """
        data = {
            'storage': {
                'type': 'TSE',
                'vendor': 'TSE1'
            },
            'function': 'RunTSESelfTest',
            'input': {},
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'EXECUTION_OK' | 'TSE1_ERROR_CLIENT_NOT_REGISTERED':
                return None
            case _:
                raise tse_ex.TSESelfTestError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def factory_reset(self) -> None:
        """
        Reset the TSE device.

        .. note::
            This method only works for development versions of the TSE device.

        You need to reboot the printer afterwards. In case of the TSE
        Server, please power cycle the TSE by removing and reinserting it.

        **Role: None**

        Raises:
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """
        data = {
            'storage': {
                'type': 'TSE',
                'vendor': 'TSE1'
            },
            'function': 'FactoryReset',
            'input': {
            },
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'EXECUTION_OK':
                return None
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def register_secret(self, secret: str) -> None:
        """
        Set a new secret for authentication.

        **Role: TSERole.ADMIN**

        Args:
            secret: The shared secret for authentication.

        Raises:
            ValueError: If secret has not exactly 8 characters.
            tse.exceptions.TSEInternalError: If an internal TSE error occurred.
                Normally, the TSE host must be restarted.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """
        data = {
            'storage': {
                'type': 'TSE',
                'vendor': 'TSE1'
            },
            'function': 'RegisterSecretKey',
            'input': {
                'secretKey': secret
            },
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'TSE1_ERROR_NOT_AUTHORIZED':
                raise tse_ex.TSEInternalError(
                    'A internal TSE error occurred. Normally, '
                    'the TSE host must be restarted.')
            case 'JSON_ERROR_INVALID_PARAMETER_RANGE':
                raise ValueError('The secret must have exactly 8 characters.')
            case 'EXECUTION_OK':
                self._secret = secret

                return None
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def update_time(self, user_id: str, time: datetime) -> None:
        """
        Update the TSE time.

        Date and time specified from POS to synchronize TSE and POS date
        and time.

        **Role: TSERole.TIME_ADMIN, TSERole.ADMIN**

        Args:
            user_id: The user who wants to set the time. This can be a
                registered client or the Administrator user. The user must
                be logged in with at least the TSERole.TIME_ADMIN role.
            time: The time as datetime type.

        Raises:
            tse.exceptions.TSEUnauthenticatedUserError: If no user logged in
                as TSERole.TIME_ADMIN.
            tse.exceptions.TSEInternalError: If an internal TSE error occurred.
                Normally, the TSE host must be restarted.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """
        data = {
            'storage': {
                'type': 'TSE',
                'vendor': 'TSE1'
            },
            'function': 'UpdateTime',
            'input': {
                'userId': user_id,
                'newDateTime': time.isoformat(timespec='seconds') + 'Z',
                'useTimeSync': False
            },
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'TSE1_ERROR_NOT_AUTHORIZED':
                raise tse_ex.TSEInternalError(
                    'A internal TSE error occurred. Normally, '
                    'the TSE host must be restarted.')
            case 'OTHER_ERROR_UNAUTHENTICATED_TIME_ADMIN_USER':
                raise tse_ex.TSEUnauthenticatedUserError(
                    f'The user "{user_id}" is not logged in with '
                    'TSERole.TIME_ADMIN or TSERole.ADMIN role.')
            case 'EXECUTION_OK':
                return None
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.')

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
            tse.exceptions.TSEInternalError: If an internal TSE error occurred.
                Normally, the TSE host must be restarted.
            tse.exceptions.TSEInUseError: If the TSE is in use.
            tse.exceptions.TSEOpenError: If the TSE is not open.
            tse.exceptions.TSEError: If an unexpected TSE error occurred.
            tse.exceptions.ConnectionTimeoutError: If a socket timeout
                occurred.
            tse.exceptions.ConnectionError: If there is no connection to
                the host.
        """
        if state:
            function = 'LockTSE'
        else:
            function = 'UnlockTSE'

        data = {
            'storage': {
                'type': 'TSE',
                'vendor': 'TSE1'
            },
            'function': function,
            'input': {},
            'compress': {
                'required': False,
                'type': ''
            }
        }

        result = self._tse_host.tse_send(
            self._tse_id, data, timeout=120)

        code = result['result']

        match code:
            case 'TSE1_ERROR_NOT_AUTHORIZED':
                raise tse_ex.TSEInternalError(
                    'A internal TSE error occurred. Normally, '
                    'the TSE host must be restarted.')
            case 'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER':
                raise tse_ex.TSEUnauthenticatedUserError(
                    'No user logged in with TSERole.ADMIN role.')
            case 'EXECUTION_OK':
                return None
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.')
