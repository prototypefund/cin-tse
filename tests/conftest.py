"""The conftest module for pytest."""
import pytest
from tse.backends.epson import TSE as EpsonTSE


def pytest_addoption(parser):
    """Add pytest command line option."""
    parser.addoption(
        '--epson_ip', action='store', default='10.0.0.2',
        help='The IP address of the Epson TSE.'
    )


@pytest.fixture(params=[pytest.param(EpsonTSE, marks=pytest.mark.epson)])
def tse(request, pytestconfig):
    """
    Yield multiple TSE backends.

    This fixture can be used to run a test for different
    backend.
    """
    if request.param == EpsonTSE:
        yield request.param(pytestconfig.getoption('epson_ip'))
