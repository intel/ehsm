import pytest
from typing import Optional, List
from pathlib import Path

from ehsm.api import Client
from ehsm.cli import options
from ehsm.cli.base import ehsm_cli, with_client
from ehsm.cli.utils import with_credential_missing_handler


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.test_enroll()
@options.test_run_quote()
@options.test_sgx_sign_bin()
@options.test_ehsm_signed_so_file()
@options.test_extra_options()
@options.test_path()
def server_test(
    client: Client,
    enroll: bool,
    run_quote: bool,
    sgx_sign_bin: Optional[str],
    ehsm_signed_so_file: Optional[str],
    extra: List[str],
    path: Optional[str],
):
    # calculate directory
    current_dir = Path(__file__).parent
    ehsm_dir = current_dir.parent
    server_test_dir = ehsm_dir / "server_tests"
    test_dir = str(server_test_dir.absolute())
    # path can be name of a file or file::method
    # e.g. test_crypto.py, test_remote_attestation.py, test_crypto.py::test_get_public_key
    if path is not None and len(path) != 0:
        test_dir = test_dir + "/" + path
    # invoke pytest
    enroll_opt = ["--enroll"] if enroll else []
    insecure_opt = ["--insecure"] if client.allow_insecure else []
    credential_opt = (
        ["--appid", client.appid, "--apikey", client.apikey] if not enroll else []
    )
    run_quote_opt = ["--run-quote"] if run_quote else []
    sgx_sign_bin_opt = (
        ["--sgx-sign-bin", sgx_sign_bin] if sgx_sign_bin is not None else []
    )
    ehsm_signed_so_file_opt = (
        ["--ehsm-signed-so-file", ehsm_signed_so_file]
        if ehsm_signed_so_file is not None
        else []
    )
    pytest.main(
        [
            test_dir,
            "-W",
            "ignore:Module already imported:pytest.PytestWarning",
            "--url",
            str(client.base_url),
            *enroll_opt,
            *insecure_opt,
            *credential_opt,
            *run_quote_opt,
            *sgx_sign_bin_opt,
            *ehsm_signed_so_file_opt,
            *extra,
        ]
    )
