from collections import OrderedDict
from typing import Dict, Optional, Union
from typing_extensions import Buffer
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import urllib.parse
import base64
import hashlib
import copy
import hmac
import time
import secrets

from ehsm.api.enums import (
    PaddingMode,
    KeySpec,
)


def params_sort_str(params: Dict) -> str:
    items = filter(lambda it: it[1] is not None, params.items())
    return urllib.parse.unquote_plus(
        urllib.parse.urlencode(OrderedDict(sorted(items, key=lambda k: k[0])))
    )


def prepare_params(payload: Optional[Dict], appid: str, apikey: str):
    """
    Add timestamp, appid and signature to request params.

    Signature is the HMAC(SHA256) of a combination of `appid`, `timestamp` (and
    `payload` if payload is specified).
    """
    # make a copy so that the input will not be affected
    payload = copy.deepcopy(payload)
    timestamp = str(int(time.time() * 1000))
    # add timestamp and appid to params
    params = OrderedDict()
    params["appid"] = appid
    params["timestamp"] = timestamp
    if payload is not None:
        # `payload` field here is for signing, the real payload is still an object
        # instead of a string
        params["payload"] = params_sort_str(payload)
    # convert params to a string using urllib
    params_str = params_sort_str(params)
    signature = str(
        base64.b64encode(
            hmac.new(
                apikey.encode("utf-8"),
                params_str.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).digest()
        ),
        "utf-8",
    )
    # append to params
    params["sign"] = signature
    if payload is not None:
        params["payload"] = payload
    return params


def str_to_base64(s: str) -> str:
    """
    Convert str to base64 encoded str
    """
    return str(base64.b64encode(s.encode("utf-8")), encoding="utf-8")


def base64_to_str(b: Union[str, Buffer]) -> str:
    """
    Convert base64 encoded str or buffer back to str
    """
    return str(base64.b64decode(b), encoding="utf-8")


def rsa_encrypt(src: str, pubkey: str, padding_mode: PaddingMode) -> str:
    """
    encrypt with RSA public key
    """
    rsakey = serialization.load_pem_public_key(
        pubkey.encode(), backend=default_backend()
    )
    if padding_mode == PaddingMode.EH_RSA_PKCS1_OAEP:
        return base64.b64encode(
            rsakey.encrypt(
                src.encode("utf-8"),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        )
    elif padding_mode == PaddingMode.EH_RSA_PKCS1:
        return base64.b64encode(
            rsakey.encrypt(
                src.encode("utf-8"),
                padding.PKCS1v15(),
            )
        )


def generate_random_key_hex(keyspec: KeySpec) -> str:
    if (
        keyspec == KeySpec.EH_AES_GCM_128
        or keyspec == KeySpec.EH_SM4_CBC
        or keyspec == KeySpec.EH_SM4_CTR
    ):
        return secrets.token_hex(8)
    elif keyspec == KeySpec.EH_AES_GCM_192:
        return secrets.token_hex(12)
    elif keyspec == KeySpec.EH_AES_GCM_256:
        return secrets.token_hex(16)
