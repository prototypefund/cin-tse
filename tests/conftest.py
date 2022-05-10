"""The conftest module for pytest."""
import pytest
from tse.epson import TSE as EpsonTSE


def pytest_addoption(parser):
    """Add pytest command line option."""
    parser.addoption(
        '--epson_tse_host_ip', action='store', default='10.0.0.2',
        help='The IP address of the Epson TSE.'
    )

    parser.addoption(
        '--epson_tse_id',
        action='store',
        default='TSE_FDDA56DAA09F7FAC125E58F45945D1E4AC9ED9133F75C310953B632B42BBBA56',
        help='The IP address of the Epson TSE.'
    )


@pytest.fixture
def epson_tse_host_ip(pytestconfig):
    """Get the value of command line option --epson_tse_host_ip."""
    return pytestconfig.getoption('epson_tse_host_ip')


@pytest.fixture
def epson_tse_id(pytestconfig):
    """Get the value of command line option --epson_tse_host_ip."""
    return pytestconfig.getoption('epson_tse_id')


@pytest.fixture(params=[pytest.param(EpsonTSE, marks=pytest.mark.epson)])
def tse(request, epson_tse_host_ip):
    """
    Yield multiple TSE backends.

    This fixture can be used to run a test for different
    backend.
    """
    if request.param == EpsonTSE:
        yield request.param(epson_tse_host_ip)
