"""The module for the Epson backend."""
import socket
import json
from datetime import datetime
from xml.etree import ElementTree
from typing import Optional
from tse import exceptions as tse_ex
from tse import TSEInfo, TSEState


class _TSEHost:
    """
    This class offers the possibility to communicate with an Epson TSE host.

    The ePOS Device XML interface is used for communication. Any device
    that provides this interface can be addressed (e.g. the Epson TSE
    server or Epson TSE printer).

    First, a socket connection to the host must be established. Then the
    respective TSE can be opened and data can be sent to it. Then the TSE
    must be closed and the socket can be closed. Normally the socket remains
    open and only the TSE is opened and closed for writing.
    If the TSE is used exclusively by only one client, then this can also
    remain open. Opening and closing before and after writing is only
    necessary if several clients share a TSE.

    .. code:: python

        tse_host = _TSEHost()

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
            tse.exceptions.HostnameError: If hostname format is not correct.
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
            tse.exceptions.TSEOpenError: If the TSE could not be opened.
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
                    return json.loads(result_element.text)
                case _:
                    raise tse_ex.TSEError(
                        f'Unexpected TSE error occures: {code}.'
                    )

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
    """The TSE protocol implementation for the Epson TSE."""

    def __init__(
            self, tse_id: str, host: str,
            ssl: bool = False, timeout: int = 3
            ) -> None:
        """Initialize the TSE instance."""
        self._tse_host = _TSEHost(host, ssl, timeout=120)
        self._tse_id = tse_id
        self._timeout = timeout

    def open(self):
        """
        Open the TSE device.

        Args:
            tse_id: The ID of the TSE device.
        """
        self._tse_host.tse_open(self._tse_id)

    @property
    def info(self):
        """Get a TSEInfo object."""
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

    def initialize(
            self, puk: str,
            admin_pin: str,
            time_admin_pin: str
            ) -> None:
        """
        Initialize the TSE device.

        The maximum length of the PUK is 6 characters and the maximum length
        for PINs is 5 characters.

        Args:
            puk: The PUK of the TSE device.
            admin_pin: The Pin of the Admin role.
            time_admin_pin: The PIN of the Time Admin role.

        Raise:
            ValueError: If the PUK or PIN is too long.
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

        return result

    def factory_reset(self) -> None:
        """
        Reset the TSE device.

        You need to reboot the printer afterwards. In case of the TSE
        Server, please power cycle the TSE by removing and reinserting it.
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

        return result

    def run_self_test(self):
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

        return result

    def close(self):
        """
        Close the TSE device.

        Args:
            tse_id: The ID of the TSE device.
        """
        self._tse_host.tse_close(self._tse_id)
