from typing import cast, List
import pytest

from ehsm.api import Client


def pytest_addoption(parser: pytest.Parser):
    parser.addoption(
        "--url",
        type=str,
        required=True,
        action="append",
        help="URL of server to be tested",
    )


@pytest.fixture
def client(request: pytest.FixtureRequest):
    server_url = cast(List[str], request.config.getoption("--url"))[0]
    if not server_url:
        raise ValueError("--url should be a valid url to test")
    client = Client(server_url, allow_insecure=True)
    client.enroll()
    return client
