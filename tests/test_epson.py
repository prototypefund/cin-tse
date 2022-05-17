"""Tests for the Epson TSE backend."""
import pytest
import socket
from datetime import datetime, timezone
from unittest.mock import patch, Mock
from tse import exceptions as tse_ex, TSEState
from tse.epson import _TSEHost, TSE


class TestTSEHostConnect:
    """Tests for the connect method."""

    def test_host_name_error(self):
        """The hostname has no valid format."""
        tse_host = _TSEHost()

        with pytest.raises(tse_ex.HostnameError):
            tse_host.connect('1d0(///&')

    def test_connection_timeout_error(self):
        """A connection timeout error occurs."""
        tse_host = _TSEHost()

        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.connect.side_effect = socket.timeout()

            with pytest.raises(tse_ex.ConnectionTimeoutError, match='timeout'):
                tse_host.connect('')

    def test_unexpected_error(self):
        """An unexpected error occurs."""
        tse_host = _TSEHost()

        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.connect.side_effect = Exception()

            with pytest.raises(tse_ex.ConnectionError):
                tse_host.connect('')

    def test_no_error(self):
        """No error occurred."""
        tse_host = _TSEHost()

        with patch('tse.epson.socket.socket') as socket_mock:
            response = '''
                <connect>
                    <data>
                        <client_id>sock1857622694</client_id>
                        <protocol_version>2</protocol_version>
                    </data>
                </connect>\x00
                '''.replace('\n', '').replace(' ', '')

            socket_mock.return_value.recv.return_value = response.encode()
            tse_host.connect('')

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

        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.recv.side_effect = OSError()
            tse_host._socket = socket_mock

            with pytest.raises(tse_ex.ConnectionClosedError):
                tse_host._send('')

    def test_connection_timeout_error(self):
        """A timeout error occurs."""
        tse_host = _TSEHost()

        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.send.side_effect = socket.timeout()
            tse_host._socket = socket_mock

            with pytest.raises(tse_ex.ConnectionTimeoutError):
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

    def test_tse_not_found_error(self):
        """A TSENotFoundError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            'TSE_ID', 'DEVICE_NOT_FOUND').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSENotFoundError):
            tse_host.tse_open('TSE_ID')

    def test_tse_in_use_error(self, epson_tse_host_ip, epson_tse_id):
        """A TSEInUseError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            epson_tse_id, 'DEVICE_IN_USE').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSEInUseError):
            tse_host.tse_open('TSE_ID')

    def test_tse_open_error(self, epson_tse_host_ip, epson_tse_id):
        """A TSEOpenError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            epson_tse_id, 'DEVICE_OPEN_ERROR').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSEOpenError):
            tse_host.tse_open('TSE_ID')

    def test_data_error(self):
        """A TSEDataError occurred."""
        response = ''

        tse_host = _TSEHost()
        send_mock = Mock()
        send_mock.return_value = response
        tse_host._send = send_mock

        with pytest.raises(tse_ex.TSEDataError):
            tse_host.tse_open('TSE_ID')


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

        result = tse_host.tse_send('TSE_ID', {})

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
                    <resultdata>{}</resultdata>
                </data>
                <data_id>0</data_id>
            </device_data>
        '''
        tse_host = _TSEHost()
        send_mock = Mock()
        send_mock.return_value = response
        tse_host._send = send_mock

        with pytest.raises(tse_ex.TSETimeoutError):
            tse_host.tse_send('TSE_ID', {})

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
                    <resultdata>{}</resultdata>
                </data>
                <data_id>0</data_id>
            </device_data>
        '''
        tse_host = _TSEHost()
        send_mock = Mock()
        send_mock.return_value = response
        tse_host._send = send_mock

        with pytest.raises(tse_ex.TSEIsBusy):
            tse_host.tse_send('TSE_ID', {})

    def test_data_error(self):
        """A TSEDataError occurred."""
        response = ''

        tse_host = _TSEHost()
        send_mock = Mock()
        send_mock.return_value = response
        tse_host._send = send_mock

        with pytest.raises(tse_ex.TSEDataError):
            tse_host.tse_send('TSE_ID', {})


class TestTSEHostTseClose:
    """Tests for the tse_close method."""

    def test_tse_in_use_error(self):
        """A TSEInUseError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            'TSE_ID', 'DEVICE_IN_USE').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSEInUseError):
            tse_host.tse_close('TSE_ID')

    def test_tse_not_open_error(self):
        """A TSEOpenError is raised."""
        tse_host = _TSEHost()
        socket_mock = Mock()
        socket_mock.recv.return_value = open_response.format(
            'TSE_ID', 'DEVICE_NOT_OPEN').encode()

        tse_host._socket = socket_mock

        with pytest.raises(tse_ex.TSENotOpenError):
            tse_host.tse_close('TSE_ID')

    def test_data_error(self):
        """A TSEDataError occurred."""
        response = ''

        tse_host = _TSEHost()
        send_mock = Mock()
        send_mock.return_value = response
        tse_host._send = send_mock

        with pytest.raises(tse_ex.TSEDataError):
            tse_host.tse_close('TSE_ID')


class TestTSEInfo:
    """Tests for the info property of TSE class."""

    def test_correct_info_object(self):
        """A correct TSEInfo instatnce returned."""
        data = {
            'function': 'GetStorageInfo',
            'output': {
                'smartInformation': {
                    'dataIntegrity': {
                        'healthStatus': 'PASS',
                        'uncorrectableECCErrors': 0
                     },
                    'eraseLifetimeStatus': {
                        'healthStatus': 'PASS',
                        'remainingEraseCounts': 100
                    },
                    'isReplacementNeeded': False,
                    'remainingTenYearsDataRetention': 98,
                    'spareBlockStatus': {
                        'healthStatus': 'PASS',
                        'remainingSpareBlocks': 100
                    },
                    'tseHealth': 'PASS'
                },
                'tseInformation': {
                    'cdcHash': '39b354cd774d45f1496e5fcb72f33e8316aea5f122be'
                    '96df4663fc6028df9f67',
                    'cdcId': 'U228111A9EFDDA56DA',
                    'certificateExpirationDate': '2022-08-11T23:59:59Z',
                    'createdSignatures': 0,
                    'hardwareVersion': 65540,
                    'hasPassedSelfTest': False,
                    'hasValidTime': False,
                    'isExportEnabledIfCspTestFails': False,
                    'isTSEUnlocked': False,
                    'isTransactionInProgress': False,
                    'lastExportExecutedDate': 'No Last Export Information',
                    'maxRegisteredClients': 100,
                    'maxSignatures': 20000000,
                    'maxStartedTransactions': 512,
                    'maxUpdateDelay': 45,
                    'registeredClients': 0,
                    'remainingSignatures': 20000000,
                    'serialNumber': '/dpW2qCff6wSXlj0WUXR5Kye2RM/dcMQlTtjK0'
                    'K7ulY=',
                    'signatureAlgorithm': 'ecdsa-plain-SHA384',
                    'softwareVersion': 65792,
                    'startedTransactions': 0,
                    'tarExportSize': 0,
                    'timeUntilNextSelfTest': 90000,
                    'tseCapacity': 13631488,
                    'tseCurrentSize': 0,
                    'tseDescription': 'BSI-K-TR-0373',
                    'tseInitializationState': 'UNINITIALIZED',
                    'tsePublicKey': 'BGsUxY6UtXt+TEWfCq/rdA5RA2VSJB4SaKRx4xlo'
                    'Ha8cP8Ub/N7k8XFUrJPnuJlgIYq1ng+xptRUkoWU6NtT8xdpUL2OUPrs'
                    'i38Kj3s8EUKvvY8IFC+YRTVY5ttor+HHJg==',
                    'vendorType': 'TSE1'
                }
            },
            'result': 'EXECUTION_OK'
        }

        with patch('tse.epson._TSEHost.connect', return_value=None):
            with patch('tse.epson._TSEHost.disconnect', return_value=None):
                with patch('tse.epson._TSEHost.tse_send', return_value=data):
                    tse = TSE('TSE_ID', '10.0.0.2')
                    tse_info = tse.info
                    del tse

        assert tse_info.public_key ==\
            'BGsUxY6UtXt+TEWfCq/rdA5RA2VSJB4SaKRx4xloHa8cP8Ub/N7k8XFUrJPnuJl'\
            'gIYq1ng+xptRUkoWU6NtT8xdpUL2OUPrsi38Kj3s8EUKvvY8IFC+YRTVY5ttor+'\
            'HHJg=='
        assert tse_info.model_name == 'TSE1'
        assert tse_info.state == TSEState.UNINITIALIZED
        assert not tse_info.has_valid_time
        assert tse_info.certificate_id == 'BSI-K-TR-0373'
        assert tse_info.certificate_expiration_date ==\
            datetime(2022, 8, 11, 23, 59, 59, tzinfo=timezone.utc)
        assert tse_info.unique_id == 'U228111A9EFDDA56DA'
        assert tse_info.serial_number ==\
            '/dpW2qCff6wSXlj0WUXR5Kye2RM/dcMQlTtjK0K7ulY='
        assert tse_info.signature_algorithm == 'ecdsa-plain-SHA384'
        assert tse_info.signature_counter == 0
        assert tse_info.remaining_signatures == 20000000
        assert tse_info.max_signatures == 20000000
        assert tse_info.registered_clients == 0
        assert tse_info.max_registered_clients == 100
        assert tse_info.max_started_transactions == 512
        assert tse_info.tar_export_size == 0
        assert tse_info.needs_self_test
        assert tse_info.api_version == '65792'


class TestTSEInitialize:
    """Tests for the initialize method of TSE class."""

    def test_puk_too_long(self, epson_tse_host_ip, epson_tse_id):
        with patch('tse.epson._TSEHost.connect', return_value=None):
            with patch('tse.epson._TSEHost.disconnect', return_value=None):
                tse = TSE('TSE_ID', '10.0.0.2')

                with pytest.raises(ValueError, match='PUK'):
                    tse.initialize('1234567', '12345', '54321')

                del tse

    def test_admin_pin_too_long(self, epson_tse_host_ip, epson_tse_id):
        with patch('tse.epson._TSEHost.connect', return_value=None):
            with patch('tse.epson._TSEHost.disconnect', return_value=None):
                tse = TSE('TSE_ID', '10.0.0.2')

                with pytest.raises(ValueError, match='Admin PIN'):
                    tse.initialize('123456', '123456', '54321')

                del tse

    def test_time_admin_pin_too_long(self, epson_tse_host_ip, epson_tse_id):
        with patch('tse.epson._TSEHost.connect', return_value=None):
            with patch('tse.epson._TSEHost.disconnect', return_value=None):
                tse = TSE('TSE_ID', '10.0.0.2')

                with pytest.raises(ValueError, match='Time Admin PIN'):
                    tse.initialize('123456', '12345', '654321')

                del tse

    # def test_tmp(self, epson_tse_host_ip, epson_tse_id):
    #     tse = TSE(epson_tse_id, epson_tse_host_ip)
    #     tse.open()
    #     # print(tse._factory_reset())
    #     # print(tse.setup('111111', '222222', '333333'))
    #     # print(tse.run_self_test())
    #     tse.close()
