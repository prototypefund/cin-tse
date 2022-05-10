"""Tests for the Epson TSE backend."""
import pytest
import socket
from unittest.mock import patch, Mock
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


class TestTSEHostSend:
    """Tests for the _send method of the _TSEHost class."""

    def test_not_connected_error(self):
        """No connection to TSE host available."""
        tse_host = _TSEHost()

        with pytest.raises(tse_ex.NotConnectedError):
            tse_host._send('')

    def test_connection_closed_error(self):
        """The connection to TSE host was closed."""
        tse_host = _TSEHost()

        with patch('tse.backends.epson.socket.socket') as socket_mock:
            socket_mock.recv.side_effect = OSError()
            tse_host._socket = socket_mock

            with pytest.raises(tse_ex.ConnectionClosedError):
                tse_host._send('')

    def test_timeout_error(self):
        """A timeout error occurs."""
        tse_host = _TSEHost()

        with patch('tse.backends.epson.socket.socket') as socket_mock:
            socket_mock.send.side_effect = socket.timeout()
            tse_host._socket = socket_mock

            with pytest.raises(tse_ex.TimeoutError):
                tse_host._send('')


open_response = '''
    <open_device>
        <device_id>{}</device_id>
        <code>{}</code>
        <data_id>1</data_id>
    </open_device>\x00
'''.replace('\n', '').replace(' ', '')


class TestTSEHostTseOpen:
    """Tests for the tse_open method."""

    def test_tse_not_found_error(self, epson_tse_host_ip, epson_tse_id):
        """A TSENotFoundError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            epson_tse_id, 'DEVICE_NOT_FOUND').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSENotFoundError):
            tse_host.tse_open('dsdsdsds')

    def test_tse_in_use_error(self, epson_tse_host_ip, epson_tse_id):
        """A TSEInUseError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            epson_tse_id, 'DEVICE_IN_USE').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSEInUseError):
            tse_host.tse_open('dsdsdsds')

    def test_tse_open_error(self, epson_tse_host_ip, epson_tse_id):
        """A TSEOpenError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            epson_tse_id, 'DEVICE_OPEN_ERROR').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSEOpenError):
            tse_host.tse_open('dsdsdsds')


class TestTSEHostTseSend:
    """Tests for the tse_open method."""

    def test_no_error(self):
        """No error occurred."""
        response = '''
            <device_data>
                <sequence>0</sequence>
                <device_id>TSE</device_id>
                <data>
                    <type>operateresult</type>
                    <success>true</success>
                    <code>SUCCESS</code>
                    <resultdata>{"test": 123}</resultdata>
                </data>
                <data_id>0</data_id>
            </device_data>
        '''
        tse_host = _TSEHost()
        send_mock = Mock()
        send_mock.return_value = response
        tse_host._send = send_mock

        result = tse_host.tse_send('', {})

        assert result == {'test': 123}

    def test_timeout_error(self):
        """A timout error occurred."""
        response = '''
            <device_data>
                <sequence>0</sequence>
                <device_id>TSE</device_id>
                <data>
                    <type>operateresult</type>
                    <success>true</success>
                    <code>ERROR_TIMEOUT</code>
                </data>
                <data_id>0</data_id>
            </device_data>
        '''
        tse_host = _TSEHost()
        send_mock = Mock()
        send_mock.return_value = response
        tse_host._send = send_mock

        with pytest.raises(tse_ex.TimeoutError):
            tse_host.tse_send('', {})

    def test_tse_is_busy(self):
        """A TSEIsBusyError occurred."""
        response = '''
            <device_data>
                <sequence>0</sequence>
                <device_id>TSE</device_id>
                <data>
                    <type>operateresult</type>
                    <success>true</success>
                    <code>ERROR_DEVICE_BUSY</code>
                </data>
                <data_id>0</data_id>
            </device_data>
        '''
        tse_host = _TSEHost()
        send_mock = Mock()
        send_mock.return_value = response
        tse_host._send = send_mock

        with pytest.raises(tse_ex.TSEIsBusy):
            tse_host.tse_send('', {})


class TestTSEHostTseClose:
    """Tests for the tse_close method."""

    def test_tse_not_found_error(self, epson_tse_host_ip, epson_tse_id):
        """A TSENotFoundError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            epson_tse_id, 'DEVICE_NOT_FOUND').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSENotFoundError):
            tse_host.tse_close('dsdsdsds')

    def test_tse_in_use_error(self, epson_tse_host_ip, epson_tse_id):
        """A TSEInUseError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            epson_tse_id, 'DEVICE_IN_USE').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSEInUseError):
            tse_host.tse_close('dsdsdsds')

    def test_tse_open_error(self, epson_tse_host_ip, epson_tse_id):
        """A TSEOpenError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            epson_tse_id, 'DEVICE_OPEN_ERROR').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSEOpenError):
            tse_host.tse_close('dsdsdsds')


# class TestTSEHostTseSend:
#     """Tests for the tse_open method."""
#
#     def test_tmp(self, epson_tse_host_ip, epson_tse_id):
#         """A TSENotFoundError is raised."""
#         data = {
#             'storage': {
#                 'type': 'COMMON',
#                 'vendor': ''
#             },
#             'function': 'GetStorageInfo',
#             'input': {},
#             'compress': {
#                 'required': False,
#                 'type': ''
#             }
#         }
#
#         tse_host = _TSEHost()
#
#         tse_host.connect(epson_tse_host_ip)
#         tse_host.tse_open(epson_tse_id)
#         print(tse_host.tse_send(epson_tse_id, data))
#         tse_host.tse_close(epson_tse_id)
#         tse_host.disconnect()
