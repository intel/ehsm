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
    parser.addoption(
        "--enroll",
        action="store_true",
        required=False,
        default=False,
        help="Enroll first",
    )
    parser.addoption(
        "--appid",
        action="store",
        required=False,
        help="An unique id to request ehsm in a domain, which is requested from ehsm service maintainer",
    )
    parser.addoption(
        "--apikey",
        action="store",
        required=False,
        help="the API access key to the eHSM-KMS server",
    )
    parser.addoption(
        "--insecure",
        action="store_true",
        required=False,
        default=False,
        help="Allow insecure request",
    )
    # for running genereateQuote and verifyQuote API test
    parser.addoption(
        "--run-quote",
        action="store_true",
        required=False,
        default=False,
        help="Run remote attestation test",
    )
    parser.addoption(
        "--sgx-sign-bin",
        action="store",
        type=str,
        required=False,
        default="/opt/intel/sgxsdk/bin/x64/sgx_sign",
        help="Path of sgx_sign binary, used in remote attestation test",
    )
    parser.addoption(
        "--ehsm-signed-so-file",
        action="store",
        type=str,
        required=False,
        help="Path of the libenclave-ehsm-core.signed.so file, used in remote attestation test",
    )


@pytest.fixture
def client(request: pytest.FixtureRequest):
    enroll = cast(bool, request.config.getoption("--enroll"))
    insecure = cast(bool, request.config.getoption("--insecure"))
    server_url = cast(List[str], request.config.getoption("--url"))[0]
    if not server_url:
        raise ValueError("--url should be a valid url to test")
    client = Client(server_url, allow_insecure=insecure)
    if enroll:
        client.enroll()
    else:
        # check if appid and apikey is provided
        appid = cast(str, request.config.getoption("--appid"))
        apikey = cast(str, request.config.getoption("--apikey"))
        client.set_appid(appid)
        client.set_apikey(apikey)
    return client


@pytest.fixture
def sgx_sign_bin(request: pytest.FixtureRequest):
    sgx_sign_bin = cast(str, request.config.getoption("--sgx-sign-bin"))
    return sgx_sign_bin


@pytest.fixture
def ehsm_signed_so_file(request: pytest.FixtureRequest):
    ehsm_signed_so_file = cast(str, request.config.getoption("--ehsm-signed-so-file"))
    return ehsm_signed_so_file
