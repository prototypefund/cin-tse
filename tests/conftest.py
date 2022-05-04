"""The conftest module for pytest."""
import pytest
from tse.backends.epson import TSE as EpsonTSE


@pytest.fixture(params=[pytest.param(EpsonTSE, marks=pytest.mark.epson)])
def tse_backend(request):
    """
    Yield multiple TSE backends.

    This fixture can be used to run a test for different
    backend.
    """
    yield request.param
