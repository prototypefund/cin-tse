"""Tests for the Epson TSE backend."""
import pytest
import socket
from unittest.mock import patch
from tse import exceptions as tse_ex
from tse.backends.epson import _TSEHost


class TestTSEHostConnect:
    """Tests for the connect method."""

    def test_host_name_error(self):
        """The hostname has no valid format."""
        tse_host = _TSEHost()

        with pytest.raises(tse_ex.ConnectError, match='hostname'):
            tse_host.connect('1d0(///&')

    def test_timeout_error(self, epson_tse_host_ip):
        """A timeout error occurs."""
        tse_host = _TSEHost()

        with patch('tse.backends.epson.socket.socket') as socket_mock:
            socket_mock.return_value.connect.side_effect = socket.timeout()

            with pytest.raises(tse_ex.ConnectError, match='timeout'):
                tse_host.connect(epson_tse_host_ip)

    def test_unexpected_error(self, epson_tse_host_ip):
        """An unexpected error occurs."""
        tse_host = _TSEHost()

        with patch('tse.backends.epson.socket.socket') as socket_mock:
            socket_mock.return_value.connect.side_effect = Exception()

            with pytest.raises(tse_ex.ConnectError, match='connection'):
                tse_host.connect(epson_tse_host_ip)

    def test_no_error(self, epson_tse_host_ip):
        """No error occurred."""
        tse_host = _TSEHost()

        with patch('tse.backends.epson.socket.socket') as socket_mock:
            response = '''
                <connect>
                    <data>
                        <client_id>sock1857622694</client_id>
                        <protocol_version>2</protocol_version>
                    </data>
                </connect>\x00
                '''.replace('\n', '').replace(' ', '')

            socket_mock.return_value.recv.return_value = response.encode()
            tse_host.connect(epson_tse_host_ip)

            assert tse_host.client_id == 'sock1857622694'
            assert tse_host.protocol_version == '2'

    def test_xtmp(self, epson_tse_host_ip):
        tse_host = _TSEHost()
        tse_host.connect(epson_tse_host_ip)
