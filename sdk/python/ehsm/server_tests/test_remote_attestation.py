import os
import pytest
import random
import tempfile
from typing import Optional

from ehsm.api import Client
from ehsm.utils import str_to_base64
from ehsm.server_tests.utils import assert_response_success, random_str


def parse_enclave_file(filename: str):
    """
    Parse an dump file of `sgx_sign -dump`
    """
    mr_enclave = ""
    mr_signer = ""
    with open(filename, "rb") as enclave_file:
        read_enclave_line_num = 0
        read_signer_line_num = 0
        for line in enclave_file.readlines():
            line = line.strip()
            if read_enclave_line_num > 0:
                read_enclave_line_num -= 1
                mr_enclave += str(line, "UTF-8").replace("0x", "").replace(" ", "")
            if read_signer_line_num > 0:
                read_signer_line_num -= 1
                mr_signer += str(line, "UTF-8").replace("0x", "").replace(" ", "")
            if line.endswith(
                "metadata->enclave_css.body.enclave_hash.m:".encode("utf-8")
            ):
                if len(mr_enclave) == 0:
                    read_enclave_line_num = 2
            if line.endswith("mrsigner->value:".encode("utf-8")):
                if len(mr_signer) == 0:
                    read_signer_line_num = 2
    return mr_enclave, mr_signer


@pytest.mark.skipif(
    "not config.getoption('--run-quote')",
    reason="Only run when --run-quote is given since this API is broken in docker environment",
)
def test_generate_quote_and_verify_quote(
    client: Client,
    sgx_sign_bin: Optional[str],
    ehsm_signed_so_file: Optional[str],
):
    # parameter check
    if sgx_sign_bin is None or not os.path.isfile(sgx_sign_bin):
        raise ValueError(
            "sgx_sign binary not found, set --sgx-sign-bin to correct this"
        )
    if ehsm_signed_so_file is None or not os.path.isfile(ehsm_signed_so_file):
        raise ValueError(
            "ehsm_signed_so_file is invalid, set --ehsm-signed-so-file to path of libenclave-ehsm-core.signed.so"
        )

    # generate a quote
    tmp_file = tempfile.NamedTemporaryFile()
    ret = os.system(
        f"{sgx_sign_bin} dump -enclave {ehsm_signed_so_file} -dumpfile {tmp_file.name}"
    )
    assert ret == 0
    mr_enclave, mr_signer = parse_enclave_file(tmp_file.name)

    # upload quote
    result = client.upload_quote_policy(mr_enclave=mr_enclave, mr_signer=mr_signer)
    assert_response_success(result.response)
    policy_id = result.policy_id
    # try get uploaded quote
    result = client.get_quote_policy(policy_id)
    assert_response_success(result.response)
    assert mr_enclave == result.mr_enclave
    assert mr_signer == result.mr_signer

    # generte quote with random challenge
    challenge = random_str(random.randint(10, 100))
    result = client.generate_quote(str_to_base64(challenge))
    assert_response_success(result.response)

    quote = result.quote
    nonce = str_to_base64(random_str(random.randint(10, 20)))

    # verify quote (policy_id is optional?)
    result = client.verify_quote(quote=quote, nonce=nonce, policy_id=policy_id)
    assert_response_success(result.response)
    is_valid = result.result
    assert is_valid

    # try an invalid one
    invalid_quote = quote[:-1] + random_str(1)
    result = client.verify_quote(
        quote=str_to_base64(invalid_quote), nonce=nonce, policy_id=policy_id
    )
    # assert invalid
    assert result.response.code != 200
