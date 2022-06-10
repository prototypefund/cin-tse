"""Tests for the Epson TSE backend."""
import pytest
import socket
from datetime import datetime, timezone
from unittest.mock import patch
from tse import exceptions as tse_ex, TSEState
from tse.epson import _TSEHost, TSE


@pytest.fixture
def connect_response():
    """Test response for the connection."""
    response = '''
        <connect>
            <data>
                <client_id>sock1857622694</client_id>
                <protocol_version>2</protocol_version>
            </data>
        </connect>\x00
        '''.replace('\n', '').replace(' ', '').encode()

    return response


class TestTSEHostInit:
    """Tests for the __init__ method."""

    def test_host_name_error(self):
        """The hostname has no valid format."""
        with pytest.raises(tse_ex.ConnectionHostnameError):
            _TSEHost('1d0(///&')

    def test_connection_timeout_error(self):
        """A connection timeout error occurs."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.connect.side_effect = socket.timeout()

            with pytest.raises(tse_ex.ConnectionTimeoutError, match='timeout'):
                _TSEHost('10.0.0.1')

    def test_unexpected_error(self):
        """An unexpected error occurs."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.connect.side_effect = Exception()

            with pytest.raises(tse_ex.ConnectionError):
                _TSEHost('')

    def test_no_error(self, connect_response):
        """No error occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.return_value = connect_response
            tse_host = _TSEHost('')

            assert tse_host.client_id == 'sock1857622694'
            assert tse_host.protocol_version == '2'


class TestTSEHostSend:
    """Tests for the _send method of the _TSEHost class."""

    @pytest.mark.parametrize('error', [OSError, AttributeError])
    def test_not_connected_error(self, error, connect_response):
        """No connection to TSE host available."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                    connect_response, error()]
            tse_host = _TSEHost('')

            with pytest.raises(tse_ex.ConnectionError):
                tse_host._send('')

    def test_connection_timeout_error(self, connect_response):
        """A timeout error occurs."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                    connect_response, socket.timeout()]
            tse_host = _TSEHost('')

            with pytest.raises(tse_ex.ConnectionTimeoutError):
                tse_host._send('')


@pytest.fixture
def open_response():
    """Test response for opening the TSE."""
    response = '''
        <open_device>
            <device_id>TSE_ID</device_id>
            <code>{}</code>
            <data_id>1</data_id>
        </open_device>\x00
    '''.replace('\n', '').replace(' ', '')

    return response


class TestTSEHostTseOpen:
    """Tests for the tse_open method."""

    def test_tse_not_found_error(self, connect_response, open_response):
        """A TSENotFoundError is raised."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
                open_response.format('DEVICE_NOT_FOUND').encode()
            ]
            tse_host = _TSEHost('')

            with pytest.raises(tse_ex.TSEOpenError):
                tse_host.tse_open('TSE_ID')

    def test_tse_in_use_error(self, connect_response, open_response):
        """A TSEInUseError is raised."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
                open_response.format('DEVICE_IN_USE').encode()
            ]
            tse_host = _TSEHost('')

            with pytest.raises(tse_ex.TSEInUseError):
                tse_host.tse_open('TSE_ID')

    def test_tse_open_error(self, connect_response, open_response):
        """A TSEOpenError is raised."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
                open_response.format('DEVICE_OPEN_ERROR').encode()
            ]
            tse_host = _TSEHost('')

            with pytest.raises(tse_ex.TSEOpenError):
                tse_host.tse_open('TSE_ID')

    def test_tse_no_error(self, connect_response, open_response):
        """A TSEOpenError is raised."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
                open_response.format('OK').encode()
            ]
            tse_host = _TSEHost('')
            tse_host.tse_open('TSE_ID')

    def test_tse_unexpected_error(self, connect_response, open_response):
        """A TSEOpenError is raised."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
                open_response.format('SOME_ERROR').encode()
            ]
            tse_host = _TSEHost('')

            with pytest.raises(tse_ex.TSEError):
                tse_host.tse_open('TSE_ID')


@pytest.fixture
def send_response():
    """Test response for sending to the TSE."""
    response = '''
        <device_data>
            <sequence>0</sequence>
            <device_id>TSE</device_id>
            <data>
                <type>operateresult</type>
                <success>true</success>
                <code>{}</code>
                <resultdata>{}</resultdata>
            </data>
            <data_id>0</data_id>
        </device_data>
    '''
    return response


class TestTSEHostTseSend:
    """Tests for the tse_open method."""

    def test_no_error(self, connect_response, send_response):
        """No error occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            response = send_response.format('SUCCESS', '{"test": 123}')

            with patch('tse.epson._TSEHost._send', return_value=response):
                tse_host = _TSEHost('')
                result = tse_host.tse_send('TSE_ID', {})

                assert result == {'test': 123}

    def test_timeout_error(self, connect_response, send_response):
        """A timout error occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            response = send_response.format('ERROR_TIMEOUT', '{}')

            with patch('tse.epson._TSEHost._send', return_value=response):
                tse_host = _TSEHost('')

                with pytest.raises(tse_ex.TSETimeoutError):
                    tse_host.tse_send('TSE_ID', {})

    def test_tse_is_busy(self, connect_response, send_response):
        """A TSEIsBusyError occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            response = send_response.format('ERROR_DEVICE_BUSY', '{}')

            with patch('tse.epson._TSEHost._send', return_value=response):
                tse_host = _TSEHost('')

                with pytest.raises(tse_ex.TSEInUseError):
                    tse_host.tse_send('TSE_ID', {})


@pytest.fixture
def close_response():
    """Test response for closing the TSE."""
    response = '''
        <close_device>
            <device_id>TSE_ID</device_id>
            <code>{}</code>
            <data_id>1</data_id>
        </close_device>\x00
    '''.replace('\n', '').replace(' ', '')

    return response


class TestTSEHostTseClose:
    """Tests for the tse_close method."""

    def test_tse_in_use_error(self, connect_response, close_response):
        """A TSEInUseError is raised."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
                close_response.format('DEVICE_IN_USE').encode()
            ]

            tse_host = _TSEHost('')

            with pytest.raises(tse_ex.TSEInUseError):
                tse_host.tse_close('TSE_ID')

    def test_tse_not_open_error(self, connect_response, close_response):
        """A TSEOpenError is raised."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
                close_response.format('DEVICE_NOT_OPEN').encode()
            ]

            tse_host = _TSEHost('')

            with pytest.raises(tse_ex.TSEOpenError):
                tse_host.tse_close('TSE_ID')


@pytest.fixture
def json_response():
    """Test response for the JSON API call."""
    response = {
        'error': {
            'errorinfo': '',
            'fact': ''
        },
        'function': 'SetUp',
        'output': {},
        'result': ''
    }

    return response


class TestTSEInfo:
    """Tests for the info property of TSE class."""

    def test_correct_info_object(self, connect_response):
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

        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response
            ]

            with patch('tse.epson._TSEHost.tse_send', return_value=data):
                tse = TSE('TSE_ID', '10.0.0.2')
                tse_info = tse.info

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

    def test_tmp(self, connect_response, json_response):
        """A correct TSEInfo instatnce returned."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response
            ]

            json_response['result'] = 'SOME_ERROR'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '10.0.0.2')

                with pytest.raises(tse_ex.TSEError):
                    tse.info


class TestTSEInitialize:
    """Tests for the initialize method of TSE class."""

    def test_puk_too_long(self, connect_response):
        """The PUK is too long."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response
            ]

            with pytest.raises(ValueError, match='PUK'):
                tse = TSE('TSE_ID', '10.0.0.2')
                tse.initialize('1234567', '12345', '54321')

    def test_admin_pin_too_long(self, connect_response):
        """The Admin PIN is too long."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response
            ]

            with pytest.raises(ValueError, match='Admin PIN'):
                tse = TSE('TSE_ID', '10.0.0.2')
                tse.initialize('123456', '123456', '54321')

    def test_time_admin_pin_too_long(self, connect_response):
        """The TimeAdmin PIN is too long."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response
            ]

            with pytest.raises(ValueError, match='Time Admin PIN'):
                tse = TSE('TSE_ID', '10.0.0.2')
                tse.initialize('123456', '12345', '654321')

    def test_tse_already_initialized(
            self, connect_response, json_response):
        """A TSEAlreadyInitializedError occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = 'OTHER_ERROR_TSE_ALREADY_SET_UP'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '10.0.0.2')

                with pytest.raises(tse_ex.TSEAlreadyInitializedError):
                    tse.initialize('123456', '12345', '54321')

    def test_tse_needs_self_test(self, connect_response, json_response):
        """A TSEAlreadyInitializedError occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = \
                'TSE1_ERROR_WRONG_STATE_NEEDS_SELF_TEST'

            with patch(
                    'tse.epson._TSEHost.tse_send',
                    return_value=json_response
                    ):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSENeedsSelfTestError):
                    tse.initialize('123456', '12345', '54321')

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = 'XYZ'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEError):
                    tse.initialize('123456', '12345', '54321')

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = \
                'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                assert not tse.initialize('123456', '12345', '54321')


class TestTSERunSelfTest:
    """Tests for the run_self_test method of TSE class."""

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = \
                'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                assert not tse.run_self_test()

    def test_client_not_registered(self, connect_response, json_response):
        """The Execution was OK if client not registered."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = \
                'TSE1_ERROR_CLIENT_NOT_REGISTERED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                assert not tse.run_self_test()

    def test_self_test_error(self, connect_response, json_response):
        """A TSESelfTestError occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = \
                'XYZ'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSESelfTestError):
                    tse.run_self_test()


class TestTSEFactoryReset:
    """Tests for the factory_reset method of TSE class."""

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = 'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                assert not tse.factory_reset()

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = 'XYZ'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEError):
                    tse.factory_reset()

    # def test_tmp(self, epson_tse_host_ip, epson_tse_id):
    #     tse = TSE(epson_tse_id, epson_tse_host_ip)
    #     tse.open()
    #     try:
    #         print(tse.info)
    #         # tse.run_self_test()
    #         # print(tse.info.state)
    #         # print(tse.initialize('123456', '12345', '54321'))
    #         # print(tse.info.state)
    #     except Exception as e:
    #         print(e)
    # #     # print(tse._factory_reset())
    # #     # print(tse.setup('111111', '222222', '333333'))
    # #     # print(tse.run_self_test())
    #     tse.close()
    #
    # def test_reset(self, epson_tse_host_ip, epson_tse_id):
    #     tse = TSE(epson_tse_id, epson_tse_host_ip)
    #     tse.open()
    #
    #     try:
    #         print(tse.factory_reset())
    #     except Exception as e:
    #         print(e)
    #
    #     tse.close()
