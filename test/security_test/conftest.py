import pytest

def pytest_addoption(parser):
    parser.addoption("--url", action="store", default="", type=str, help='the address of the ehsm_kms_server')#, required=True)

@pytest.fixture
def test_url(request):
    return request.config.getoption("--url")
