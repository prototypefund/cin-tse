"""Tests for the Epson TSE backend."""
import pytest
import socket
from datetime import datetime, timezone
from unittest.mock import patch
from tse import exceptions as tse_ex, TSEState, TSERole, TSETransaction
from tse.epson import _TSEHost, TSE, _hash


class TestHash:
    """Tests for the _hash function."""

    def test_hash_correct(self):
        """Is the hash correct."""
        result = _hash('jdsdsdsdjdsdj', 'EPSONKEY')

        assert result == b'wWM1Xcd0qrctlQwpvBMg3x0t9h/tgAg2qhTlxTX8V4A='


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

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
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


class TestGetChallenge:
    """Tests for the _get_challenge method of the TSE class."""

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response
            ]

            json_response['result'] = 'SOME_ERROR'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '10.0.0.2')

                with pytest.raises(tse_ex.TSEError):
                    tse._get_challenge('Administrator')

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response
            ]

            json_response['result'] = 'EXECUTION_OK'
            json_response['output'] = {'challenge': 'JSUJEEKSK6789'}

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '10.0.0.2')

                assert tse._get_challenge('Administrator') == 'JSUJEEKSK6789'


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

            json_response['result'] = 'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                assert not tse.initialize('123456', '12345', '54321')

    def test_certificate_expired(self, json_response):
        """The certificate was expired."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'TSE1_ERROR_CERTIFICATE_EXPIRED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEError):
                    tse.initialize('123456', '12345', '54321')


class TestLoginUser:
    """Tests for the authenticate_user method of TSE class."""

    def test_wrong_admin_user(self, connect_response, json_response):
        """Wrong user for Admin role (only Administrator allowed)."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = 'OTHER_ERROR_INVALID_ADMIN_USER_ID'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):

                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response
                        ):

                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSELoginError):
                        tse.login_user(
                            'xyz', TSERole.ADMIN, '12345')

    def test_login_error(self, connect_response, json_response):
        """A login error occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = 'TSE1_ERROR_AUTHENTICATION_FAILED'
            json_response['output'] = {'remainingRetries': 2}

            with patch('tse.epson.TSE._get_challenge', return_value='123'):

                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response
                        ):

                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSELoginError):
                        tse.login_user(
                            'xyz', TSERole.TIME_ADMIN, '12345')

    def test_correct_admin_user(self, connect_response, json_response):
        """The Administrator user logged in."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = 'EXECUTION_OK'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):

                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response
                        ):

                    tse = TSE('TSE_ID', '')

                    assert not tse.login_user(
                            'xyz', TSERole.ADMIN, '12345')

    def test_pin_blocked(self, connect_response, json_response):
        """The PIN was blocked."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = 'TSE1_ERROR_AUTHENTICATION_PIN_BLOCKED'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):

                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response
                        ):

                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEPinBlockedError):
                        tse.login_user(
                                'xyz', TSERole.ADMIN, '12345')

    def test_secret_error(self, connect_response, json_response):
        """The secret was wrong."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = 'OTHER_ERROR_HOST_AUTHENTICATION_FAILED'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response
                        ):

                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSESecretError):
                        tse.login_user(
                                'xyz', TSERole.ADMIN, '12345')

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
        with patch('tse.epson.socket.socket') as socket_mock:
            socket_mock.return_value.recv.side_effect = [
                connect_response,
            ]

            json_response['result'] = 'XYZ'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response
                        ):

                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEError):
                        tse.login_user(
                                'xyz', TSERole.ADMIN, '12345')

    def test_puk_change_required(self, json_response):
        """A PUK change is required."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'TSE1_ERROR_WRONG_STATE_NEEDS_PUK_CHANGE'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response):
                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEPukStateError):
                        tse.login_user(
                                'xyz', TSERole.ADMIN, '12345')

    def test_pin_change_required(self, json_response):
        """A PIN change is required."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'TSE1_ERROR_WRONG_STATE_NEEDS_PIN_CHANGE'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response):
                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEPinStateError):
                        tse.login_user(
                                'xyz', TSERole.ADMIN, '12345')


class TestLogoutUser:
    """Tests for the logout_user method of TSE class."""

    def test_logout_successful(self, json_response):
        """The logout was successful."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                assert not tse.logout_user('Administrator', TSERole.ADMIN)

    def test_no_admin_user_logged_in(self, json_response):
        """There is no logged in Admin user."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSELogoutError):
                    tse.logout_user('Administrator', TSERole.ADMIN)

    def test_wrong_admin_user(self, json_response):
        """There is no logged in Admin user."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            tse = TSE('TSE_ID', '')

            with pytest.raises(tse_ex.TSELogoutError):
                tse.logout_user('user', TSERole.ADMIN)

    def test_user_not_time_admin(self, json_response):
        """There is no logged in TimeAdmin user."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'OTHER_ERROR_UNAUTHENTICATED_TIME_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSELogoutError):
                    tse.logout_user('Administrator', TSERole.ADMIN)

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response
                        ):

                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEError):
                        tse.logout_user('xyz', TSERole.TIME_ADMIN)


class TestChangePin:
    """Tests for the change_pin method of TSE class."""

    def test_puk_change_required(self, json_response):
        """A PUK change is required."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response_ok = json_response.copy()
            json_response_change_pin = json_response.copy()
            json_response_ok['result'] = 'EXECUTION_OK'
            json_response_change_pin['result'] = \
                'TSE1_ERROR_WRONG_STATE_NEEDS_PUK_CHANGE'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        side_effect=[
                            json_response_ok,
                            json_response_change_pin,
                            json_response_ok]):
                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEPukStateError):
                        tse.change_pin(TSERole.ADMIN, '123456', '12345')

    def test_pin_change_required(self, json_response):
        """A PIN change is required."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response_ok = json_response.copy()
            json_response_change_pin = json_response.copy()
            json_response_ok['result'] = 'EXECUTION_OK'
            json_response_change_pin['result'] = \
                'TSE1_ERROR_WRONG_STATE_NEEDS_PIN_CHANGE'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        side_effect=[
                            json_response_ok,
                            json_response_change_pin,
                            json_response_ok]):
                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEPinStateError):
                        tse.change_pin(TSERole.ADMIN, '123456', '12345')

    def test_needs_self_test(self, json_response):
        """The TSE needs self test."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response_ok = json_response.copy()
            json_response_change_pin = json_response.copy()
            json_response_ok['result'] = 'EXECUTION_OK'
            json_response_change_pin['result'] = \
                'TSE1_ERROR_WRONG_STATE_NEEDS_SELF_TEST'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        side_effect=[
                            json_response_ok,
                            json_response_change_pin,
                            json_response_ok]):
                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSENeedsSelfTestError):
                        tse.change_pin(TSERole.ADMIN, '123456', '12345')

    def test_pin_blocked(self, json_response):
        """The PIN is blocked."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response_ok = json_response.copy()
            json_response_change_pin = json_response.copy()
            json_response_ok['result'] = 'EXECUTION_OK'
            json_response_change_pin['result'] = \
                'TSE1_ERROR_AUTHENTICATION_PIN_BLOCKED'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        side_effect=[
                            json_response_ok,
                            json_response_change_pin,
                            json_response_ok]):
                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEAuthenticationError):
                        tse.change_pin(TSERole.ADMIN, '123456', '12345')

    def test_wrong_puk(self, json_response):
        """The PUK is wrong."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response_ok = json_response.copy()
            json_response_change_pin = json_response.copy()
            json_response_ok['result'] = 'EXECUTION_OK'
            json_response_change_pin['result'] = \
                'TSE1_ERROR_AUTHENTICATION_FAILED'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        side_effect=[
                            json_response_ok,
                            json_response_change_pin,
                            json_response_ok]):
                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEAuthenticationError):
                        tse.change_pin(TSERole.ADMIN, '123456', '12345')

    def test_certificate_expired(self, json_response):
        """The certificate is expired."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response_ok = json_response.copy()
            json_response_change_pin = json_response.copy()
            json_response_ok['result'] = 'EXECUTION_OK'
            json_response_change_pin['result'] = \
                'TSE1_ERROR_CERTIFICATE_EXPIRED'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        side_effect=[
                            json_response_ok,
                            json_response_change_pin,
                            json_response_ok]):
                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSECertificateExpiredError):
                        tse.change_pin(TSERole.ADMIN, '123456', '12345')

    def test_same_pin(self, json_response):
        """The PIN is same as before."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response_ok = json_response.copy()
            json_response_change_pin = json_response.copy()
            json_response_ok['result'] = 'EXECUTION_OK'
            json_response_change_pin['result'] = \
                'TSE1_ERROR_TSE_INVALID_PARAMETER'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        side_effect=[
                            json_response_ok,
                            json_response_change_pin,
                            json_response_ok]):
                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEPinError):
                        tse.change_pin(TSERole.ADMIN, '123456', '12345')

    def test_execution_ok(self, json_response):
        """All PIN was set successful."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response_ok = json_response.copy()
            json_response_change_pin = json_response.copy()
            json_response_ok['result'] = 'EXECUTION_OK'
            json_response_change_pin['result'] = \
                'EXECUTION_OK'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        side_effect=[
                            json_response_ok,
                            json_response_change_pin,
                            json_response_ok]):
                    tse = TSE('TSE_ID', '')

                    tse.change_pin(TSERole.ADMIN, '123456', '12345')

    def test_unexpected_error(self, json_response):
        """An unexpected error occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response_ok = json_response.copy()
            json_response_change_pin = json_response.copy()
            json_response_ok['result'] = 'EXECUTION_OK'
            json_response_change_pin['result'] = \
                'UNEXPECTED ERROR'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        side_effect=[
                            json_response_ok,
                            json_response_change_pin,
                            json_response_ok]):
                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEError):
                        tse.change_pin(TSERole.ADMIN, '123456', '12345')


class TestRegisterClient:
    """Tests for the register_client method of TSE class."""

    def test_client_registered(self, json_response):
        """The client was registered."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                assert not tse.register_client('POS1')

    def test_no_admin_user_logged_in(self, json_response):
        """There is no logged in Admin user."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEUnauthenticatedUserError):
                    tse.register_client('POS1')

    def test_max_length_error(self, json_response):
        """Client ID too long."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'JSON_ERROR_INVALID_PARAMETER_RANGE'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(ValueError):
                    tse.register_client(31*'x')

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response
                        ):

                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEError):
                        tse.register_client('xyz')


class TestDeregisterClient:
    """Tests for the deregister_client method of TSE class."""

    def test_client_registered(self, json_response):
        """The client was registered."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                assert not tse.deregister_client('POS1')

    def test_no_admin_user_logged_in(self, json_response):
        """There is no logged in Admin user."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEUnauthenticatedUserError):
                    tse.deregister_client('POS1')

    def test_max_length_error(self, json_response):
        """Client ID too long."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'JSON_ERROR_INVALID_PARAMETER_RANGE'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(ValueError):
                    tse.deregister_client(31*'x')

    def test_client_not_exist(self, json_response):
        """Client ID not exist."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'TSE1_ERROR_CLIENT_NOT_REGISTERED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEClientNotExistError):
                    tse.deregister_client(31*'x')

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response
                        ):

                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEError):
                        tse.deregister_client('xyz')


class TestTSEClientList:
    """Tests for the client_list method of the TSE class."""

    def test_all_clients_returned(self, json_response):
        """All clients returend successful."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'
            json_response['output'] = {
                    'registeredClientIdList': ['POS1', 'POS2']}

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                assert tse.client_list() == ['POS1', 'POS2']

    def test_no_admin_user_logged_in(self, json_response):
        """There is no logged in Admin user."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEUnauthenticatedUserError):
                    tse.client_list()

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch('tse.epson.TSE._get_challenge', return_value='123'):
                with patch(
                        'tse.epson._TSEHost.tse_send',
                        return_value=json_response
                        ):

                    tse = TSE('TSE_ID', '')

                    with pytest.raises(tse_ex.TSEError):
                        tse.client_list()


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

                with pytest.raises(tse_ex.TSENotInitializedError):
                    tse.run_self_test()

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


class TestTSERegisterSecret:
    """Tests for the register_secret method of TSE class."""

    def test_wrong_secret_length(self, json_response):
        """Secret has not 8 characters."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'JSON_ERROR_INVALID_PARAMETER_RANGE'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(ValueError):
                    tse.register_secret('gg')

    def test_unauthenticated_user(self, json_response):
        """It is an unauthenticated user."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'JSON_ERROR_INVALID_PARAMETER_RANGE'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(ValueError):
                    tse.register_secret('gg')

    def test_secret_correct_length(self, json_response):
        """Secret has 8 characters."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                assert not tse.register_secret('gg')


class TestTSEUpdateTime:
    """Tests for the update_time method of the TSE class."""

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                assert not tse.update_time(
                        'Administrator', datetime(2022, 8, 11, 23, 59, 59))

    def test_internal_error(self, json_response):
        """An internal error occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'TSE1_ERROR_NOT_AUTHORIZED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEInternalError):
                    tse.update_time(
                        'Administrator', datetime(2022, 8, 11, 23, 59, 59))

    def test_unauthenticated_user(self, json_response):
        """The user in unauthenticated."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'OTHER_ERROR_UNAUTHENTICATED_TIME_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEUnauthenticatedUserError):
                    tse.update_time(
                        'TEST', datetime(2022, 8, 11, 23, 59, 59))

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEError):
                    tse.update_time(
                        'TEST', datetime(2022, 8, 11, 23, 59, 59))

    def test_decommissioned_error(self, json_response):
        """The TSE is decommissioned."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'TSE1_ERROR_TSE_DECOMMISSIONED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEDecommissionedError):
                    tse.update_time(
                        'TEST', datetime(2022, 8, 11, 23, 59, 59))


class TestTSELock:
    """Tests for the lock method of the TSE class."""

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                assert not tse.lock(True)

    def test_internal_error(self, json_response):
        """An internal error occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'TSE1_ERROR_NOT_AUTHORIZED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEInternalError):
                    tse.lock(True)

    def test_unauthenticated_user(self, json_response):
        """The user in unauthenticated."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEUnauthenticatedUserError):
                    tse.lock(True)

    def test_unexpected_error(self, connect_response, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEError):
                    tse.lock(True)


class TestTSEDisableSecureElement:
    """Tests for the disable_secure_element method of the TSE class."""

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                assert not tse.disable_secure_element()

    def test_internal_error(self, json_response):
        """An internal error occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'TSE1_ERROR_NOT_AUTHORIZED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEInternalError):
                    tse.disable_secure_element()

    def test_unauthenticated_user(self, json_response):
        """The user in unauthenticated."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'OTHER_ERROR_UNAUTHENTICATED_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEUnauthenticatedUserError):
                    tse.disable_secure_element()

    def test_decommissioned_error(self, json_response):
        """The TSE is decommissioned."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'TSE1_ERROR_TSE_DECOMMISSIONED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEDecommissionedError):
                    tse.disable_secure_element()

    def test_time_not_set(self, json_response):
        """The TSE time is not set."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'TSE1_ERROR_NO_TIME_SET'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSETimeNotSetError):
                    tse.disable_secure_element()

    def test_unfinished_transactions(self, json_response):
        """There are unfinished tranactions."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'TSE1_ERROR_TSE_HAS_UNFINISHED_TRANSACTIONS'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEUnfinishedTransactionError):
                    tse.disable_secure_element()

    def test_unexpected_error(self, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEError):
                    tse.disable_secure_element()


class TestStartTransaction:
    """Tests for te start_transaction method of the TSE class."""

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'
            json_response['output'] = {
                    'logTime': '2022-07-11T23:59:59Z',
                    'serialNumber': '/dpW2qCff6wSXlj0WUXR5Kye2' +
                    'RM/dcMQlTtjK0K7ulY=',
                    'signature':
                    'fXk08EhlHB6EUST/qrKZglzZ+Yzmm2/Y7nlp/w2tm' +
                    '4I0rJlRzs7nwJVnr7yijatdTML5PTLLUzPjsMNAYHiGfuF' +
                    '7qBt+MII1/HUTQnnH7JeM5Qe1NduQeiRv2yI66Xrf',
                    'signatureCounter': 424,
                    'transactionNumber': 3
                    }

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                transaction = tse.start_transaction('pos123', 'data', 'type')

                assert transaction.number == 3
                assert transaction.serial_number == \
                    '/dpW2qCff6wSXlj0WUXR5Kye2RM/dcMQlTtjK0K7ulY='
                assert transaction.start_signature.time == \
                    datetime(2022, 7, 11, 23, 59, 59, tzinfo=timezone.utc)
                assert transaction.start_signature.value == \
                    'fXk08EhlHB6EUST/qrKZglzZ+Yzmm2/Y7nlp/w2tm' \
                    '4I0rJlRzs7nwJVnr7yijatdTML5PTLLUzPjsMNAYHiGfuF' \
                    '7qBt+MII1/HUTQnnH7JeM5Qe1NduQeiRv2yI66Xrf'
                assert transaction.start_signature.counter == 424

    def test_unauthenticated_user(self, json_response):
        """No time admin logged in."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                    'OTHER_ERROR_UNAUTHENTICATED_TIME_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEUnauthenticatedUserError):
                    tse.start_transaction('pos123', 'data', 'type')

    def test_certificate_expired(self, json_response):
        """The certificate is expired."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                    'TSE1_ERROR_CERTIFICATE_EXPIRED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSECertificateExpiredError):
                    tse.start_transaction('pos123', 'data', 'type')

    def test_time_not_set(self, json_response):
        """The time was not set."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                    'TSE1_ERROR_NO_TIME_SET'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSETimeNotSetError):
                    tse.start_transaction('pos123', 'data', 'type')

    def test_unexpected_error(self, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEError):
                    tse.start_transaction('pos123', 'data', 'type')


class TestUpdateTransaction:
    """Tests for te update_transaction method of the TSE class."""

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'
            json_response['output'] = {
                    'logTime': '2022-07-11T23:59:59Z',
                    'signature':
                    'fXk08EhlHB6EUST/qrKZglzZ+Yzmm2/Y7nlp/w2tm' +
                    '4I0rJlRzs7nwJVnr7yijatdTML5PTLLUzPjsMNAYHiGfuF' +
                    '7qBt+MII1/HUTQnnH7JeM5Qe1NduQeiRv2yI66Xrf',
                    'signatureCounter': 424,
                    }

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                transaction = TSETransaction(number=1, serial_number='s7d7')
                tse.update_transaction('pos123', transaction, 'data', 'type')

                assert transaction.number == 1
                assert transaction.serial_number == 's7d7'
                assert transaction.update_signature.time == \
                    datetime(2022, 7, 11, 23, 59, 59, tzinfo=timezone.utc)
                assert transaction.update_signature.value == \
                    'fXk08EhlHB6EUST/qrKZglzZ+Yzmm2/Y7nlp/w2tm' \
                    '4I0rJlRzs7nwJVnr7yijatdTML5PTLLUzPjsMNAYHiGfuF' \
                    '7qBt+MII1/HUTQnnH7JeM5Qe1NduQeiRv2yI66Xrf'
                assert transaction.update_signature.counter == 424

    def test_unauthenticated_user(self, json_response):
        """No time admin logged in."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                    'OTHER_ERROR_UNAUTHENTICATED_TIME_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')
                transaction = TSETransaction(number=1, serial_number='s7d7')

                with pytest.raises(tse_ex.TSEUnauthenticatedUserError):
                    tse.update_transaction(
                            'pos123', transaction, 'data', 'type')

    def test_certificate_expired(self, json_response):
        """The certificate is expired."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                    'TSE1_ERROR_CERTIFICATE_EXPIRED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')
                transaction = TSETransaction(number=1, serial_number='s7d7')

                with pytest.raises(tse_ex.TSECertificateExpiredError):
                    tse.update_transaction(
                            'pos123', transaction, 'data', 'type')

    def test_time_not_set(self, json_response):
        """The time was not set."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                    'TSE1_ERROR_NO_TIME_SET'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')
                transaction = TSETransaction(number=1, serial_number='s7d7')

                with pytest.raises(tse_ex.TSETimeNotSetError):
                    tse.update_transaction(
                            'pos123', transaction, 'data', 'type')

    def test_unexpected_error(self, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')
                transaction = TSETransaction(number=1, serial_number='s7d7')

                with pytest.raises(tse_ex.TSEError):
                    tse.update_transaction(
                            'pos123', transaction, 'data', 'type')


class TestFinishTransaction:
    """Tests for te finish_transaction method of the TSE class."""

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'
            json_response['output'] = {
                    'logTime': '2022-07-11T23:59:59Z',
                    'signature':
                    'fXk08EhlHB6EUST/qrKZglzZ+Yzmm2/Y7nlp/w2tm' +
                    '4I0rJlRzs7nwJVnr7yijatdTML5PTLLUzPjsMNAYHiGfuF' +
                    '7qBt+MII1/HUTQnnH7JeM5Qe1NduQeiRv2yI66Xrf',
                    'signatureCounter': 424,
                    }

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                transaction = TSETransaction(number=1, serial_number='s7d7')
                tse.finish_transaction('pos123', transaction, 'data', 'type')

                assert transaction.number == 1
                assert transaction.serial_number == 's7d7'
                assert transaction.finish_signature.time == \
                    datetime(2022, 7, 11, 23, 59, 59, tzinfo=timezone.utc)
                assert transaction.finish_signature.value == \
                    'fXk08EhlHB6EUST/qrKZglzZ+Yzmm2/Y7nlp/w2tm' \
                    '4I0rJlRzs7nwJVnr7yijatdTML5PTLLUzPjsMNAYHiGfuF' \
                    '7qBt+MII1/HUTQnnH7JeM5Qe1NduQeiRv2yI66Xrf'
                assert transaction.finish_signature.counter == 424

    def test_unauthenticated_user(self, json_response):
        """No time admin logged in."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                    'OTHER_ERROR_UNAUTHENTICATED_TIME_ADMIN_USER'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')
                transaction = TSETransaction(number=1, serial_number='s7d7')

                with pytest.raises(tse_ex.TSEUnauthenticatedUserError):
                    tse.finish_transaction(
                            'pos123', transaction, 'data', 'type')

    def test_certificate_expired(self, json_response):
        """The certificate is expired."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                    'TSE1_ERROR_CERTIFICATE_EXPIRED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')
                transaction = TSETransaction(number=1, serial_number='s7d7')

                with pytest.raises(tse_ex.TSECertificateExpiredError):
                    tse.finish_transaction(
                            'pos123', transaction, 'data', 'type')

    def test_time_not_set(self, json_response):
        """The time was not set."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                    'TSE1_ERROR_NO_TIME_SET'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')
                transaction = TSETransaction(number=1, serial_number='s7d7')

                with pytest.raises(tse_ex.TSETimeNotSetError):
                    tse.finish_transaction(
                            'pos123', transaction, 'data', 'type')

    def test_unexpected_error(self, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')
                transaction = TSETransaction(number=1, serial_number='s7d7')

                with pytest.raises(tse_ex.TSEError):
                    tse.finish_transaction(
                            'pos123', transaction, 'data', 'type')


class TestStartedTransactionList:
    """Tests for te started_transaction_list method of the TSE class."""

    def test_execution_ok(self, connect_response, json_response):
        """The Execution was OK."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'EXECUTION_OK'
            json_response['output'] = {'startedTransactionNumberList': [1, 3]}

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):

                tse = TSE('TSE_ID', '')

                assert tse.started_transaction_list('pos123') == [1, 3]

    def test_tse_needs_self_test(self, json_response):
        """A TSEAlreadyInitializedError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'TSE1_ERROR_WRONG_STATE_NEEDS_SELF_TEST'

            with patch(
                    'tse.epson._TSEHost.tse_send',
                    return_value=json_response
                    ):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSENeedsSelfTestError):
                    tse.started_transaction_list('pos123')

    def test_tse_needs_self_test_passed(self, json_response):
        """A TSEAlreadyInitializedError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'TSE1_ERROR_WRONG_STATE_NEEDS_SELF_TEST_PASSED'

            with patch(
                    'tse.epson._TSEHost.tse_send',
                    return_value=json_response
                    ):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSENeedsSelfTestError):
                    tse.started_transaction_list('pos123')

    def test_decommissioned_error(self, json_response):
        """The TSE is decommissioned."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = \
                'TSE1_ERROR_TSE_DECOMMISSIONED'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEDecommissionedError):
                    tse.started_transaction_list('pos123')

    def test_unexpected_error(self, json_response):
        """A TSEError occurred."""
        with patch('tse.epson._TSEHost.__init__', return_value=None):
            json_response['result'] = 'XYZ'

            with patch(
                    'tse.epson._TSEHost.tse_send', return_value=json_response):
                tse = TSE('TSE_ID', '')

                with pytest.raises(tse_ex.TSEError):
                    tse.started_transaction_list('pos123')

    # def test_tmp(self, epson_tse_host_ip, epson_tse_id):
    #     date_time = datetime(2022, 7, 11, 23, 59, 59)
    # #
    #     tse = TSE(epson_tse_id, epson_tse_host_ip)
    #     tse.open()
    #
    #     try:
    #         # tse.factory_reset()
    #         # tse.initialize('123456', '12345', '54321')
    #         # tse.run_self_test()
    #         # tse.register_secret('EPSONKEY')
    #         # print(tse._get_challenge())
    #         # tse.initialize('123456', '12345', '54321')
    #         # tse.login_user('Administrator', TSERole.ADMIN, '12345')
    #         # tse.login_user('pos123', TSERole.TIME_ADMIN, '54321')
    #         # tse.logout_user('pos123', TSERole.TIME_ADMIN)
    #         # tse.register_client('pos456')
    #         # tse.deregister_client('test')
    #         # tse.change_pin(TSERole.TIME_ADMIN, '123456', '54321')
    #         # print(tse.client_list())
    #         # tse.update_time('pos123', date_time)
    #         # transaction = tse.start_transaction('pos456', 'data', 'type')
    #         # print(transaction)
    #         # print('\n')
    #         # tse.update_transaction('pos123', transaction, 'data', 'type')
    #         # print(transaction)
    #         # print('\n')
    #         # tse.finish_transaction('pos123', transaction, 'data', 'type')
    #         # print(transaction)
    #         # print('\n')
    #
    #         print(tse.started_transaction_list(''))
    #
    #         # print(transaction.log_time)
    #         # print(transaction.serial_number)
    #         # print(transaction.signature)
    #         # print(transaction.signature_counter)
    #         #
    #         # tse.lock(False)
    #         # print(tse.info)
    #         # print(tse.disable_secure_element())
    #     except Exception as e:
    #         print(e)
    #     tse.close()
