from collections import OrderedDict
import urllib.parse
import base64
import hashlib
import copy
import hmac
import time


def prepare_params(params: OrderedDict, appid: str, appkey: str):
    """
    Add timestamp, appid and signature to request params.
    """
    # make a copy so that the input will not be affected
    params = copy.deepcopy(params)
    timestamp = str(int(time.time() * 1000))
    # add timestamp and appid to params
    params["appid"] = appid
    params["timestamp"] = timestamp
    # convert params to a string using urllib
    params_str = urllib.parse.unquote_plus(urllib.parse.urlencode(params))
    signature = str(
        base64.b64encode(
            hmac.new(
                appkey.encode("utf-8"),
                params_str.encode("utf-8"),
                digestmod=hashlib.sha256,
            ).digest()
        ),
        "utf-8",
    ).upper()
    # append to params
    params["sign"] = signature
    return params
