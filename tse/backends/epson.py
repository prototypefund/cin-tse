"""The module for the Epson backend."""
import socket
import json
from xml.etree import ElementTree
from typing import Optional
from tse import exceptions as tse_ex


class _TSEHost:
    """_TSEHost class."""

    def __init__(self) -> None:
        """Initialize the TSEHost instance."""
        self._client_id: Optional[str] = None
        self._protocol_version: Optional[str] = None

    @property
    def client_id(self):
        return self._client_id

    @property
    def protocol_version(self):
        return self._protocol_version

    def connect(self, host: str, ssl: bool = False, timeout: int = 3) -> None:
        """Connect to the TSE host."""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(timeout)

            if ssl:
                self._socket.connect((host, 8143))
            else:
                self._socket.connect((host, 8009))

            response = self._socket.recv(1024)

            root = ElementTree.fromstring(response.decode().rstrip('\x00'))
            client_id_element = root.find('*/client_id')
            protocol_version_element = root.find('*/protocol_version')

            if client_id_element.text and protocol_version_element.text:
                self._client_id = client_id_element.text
                self._protocol_version = protocol_version_element.text

        except socket.gaierror:
            raise tse_ex.ConnectError(
                f'The connection to the host "{host}" could not'
                'be established. The hostname has no valid format'
            )

        except socket.timeout:
            raise tse_ex.ConnectError(
                f'The connection to the host "{host}" could not'
                'be established. A timeout error occurs.'
            )

        except Exception:
            raise tse_ex.ConnectError(
                f'The connection to the host "{host}" could not'
                'be established.'
            )

    def _send(self, xml: str) -> str:
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

        except AttributeError:
            raise tse_ex.NotConnectedError(
                'No connection to TSE host available. Please connect.'
            )

        except socket.timeout:
            raise tse_ex.TimeoutError(
                'The data could not be sent to the TSE host. '
                'Timeout error occurs.'
            )

        except OSError:
            raise tse_ex.ConnectionClosedError(
                'The connection was closed. Please connect again.'
            )

    def tse_open(self, tse_id: str) -> None:
        """Open the TSE."""
        xml = '''
            <open_device>
                <device_id>{}</device_id>
                <data>
                    <type>type_storage</type>
                </data>
            </open_device>
            '''.format(tse_id)

        root = ElementTree.fromstring(self._send(xml))
        code = root.find('./code').text

        match code:
            case 'DEVICE_NOT_FOUND':
                raise tse_ex.TSENotFoundError(
                    f'The TSE {tse_id} was not found.'
                )
            case 'DEVICE_IN_USE':
                raise tse_ex.TSEInUseError(
                    'The TSE {tse_id} is in use.'
                )
            case 'DEVICE_OPEN_ERROR':
                raise tse_ex.TSEOpenError(
                    'The TSE {tse_id} could not be opened.'
                )
            case 'OK':
                pass
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def tse_send(self, tse_id: str, data: dict, timeout: int = 3) -> dict:
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

        root = ElementTree.fromstring(self._send(xml))
        code = root.find('./data/code').text
        result = root.find('./data/resultdata')

        print(code)

        match code:
            case 'ERROR_TIMEOUT':
                raise tse_ex.TimeoutError(
                    'A timeout error occurred while sending data to the TSE'
                )
            case 'ERROR_DEVICE_BUSY':
                raise tse_ex.TSEIsBusy(
                    'The tse is busy.'
                )
            case 'SUCCESS':
                return json.loads(result.text)
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def tse_close(self, tse_id: str) -> None:
        """Colse the TES."""
        xml = '''
            <close_device>
                <device_id>{}</device_id>
            </close_device>
            '''.format(tse_id)

        root = ElementTree.fromstring(self._send(xml))
        code = root.find('./code').text

        match code:
            case 'DEVICE_NOT_FOUND':
                raise tse_ex.TSENotFoundError(
                    f'The TSE {tse_id} was not found.'
                )
            case 'DEVICE_IN_USE':
                raise tse_ex.TSEInUseError(
                    'The TSE {tse_id} is in use.'
                )
            case 'DEVICE_OPEN_ERROR':
                raise tse_ex.TSEOpenError(
                    'The TSE {tse_id} could not be opened.'
                )
            case 'DEVICE_NOT_OPEN':
                raise tse_ex.TSENotOpenError(
                    'The TSE {tse_id} is not open.'
                )
            case 'OK':
                pass
            case _:
                raise tse_ex.TSEError(
                    f'Unexpected TSE error occures: {code}.'
                )

    def disconnect(self) -> None:
        """Disconnect the TSE host connection."""
        self._socket.close()


class TSE():
    """The TSE protocol implementation for the Epson TSE."""

    def __init__(self, host: str, ssl: bool = False) -> None:
        """Initialize the TSE instance."""
        self._host = host
        self._ssl = ssl
