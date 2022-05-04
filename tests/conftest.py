import pytest
from tse.backends.epson import TSE as EpsonTSE


@pytest.fixture(params=[pytest.param(EpsonTSE, marks=pytest.mark.epson)])
def tse_backend(request):
    yield request.param
