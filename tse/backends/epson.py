"""The module for the Epson backend."""
import socket
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

    def tse_open(tse_id: str) -> None:
        """Open the TSE."""
        pass

    def tse_close(tse_id: str) -> None:
        """Colse the TES."""
        pass

    def disconnect(self) -> None:
        """Disconnect the TSE host connection."""
        self._socket.close()


class TSE():
    """The TSE protocol implementation for the Epson TSE."""

    def __init__(self, host: str, ssl: bool = False) -> None:
        """Initialize the TSE instance."""
        self._host = host
        self._ssl = ssl
