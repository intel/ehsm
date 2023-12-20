from functools import partial
from typing import Dict, Optional
from pytest import MonkeyPatch
import pytest

from ehsm.api import Client
from ehsm.api.enums import KeySpec, KeyUsage, Origin
from ehsm.exceptions import InvalidParamException
from ehsm.utils import prepare_params
from ehsm.session import Session
from ehsm.server_tests.utils import random_str


def test_request_with_invalid_sign(client: Client):
    post_method = Session.post

    def mock_post(
        self: Session,
        url: str,
        data: Optional[Dict] = None,
        *,
        with_signature: bool = False,
        **kwargs,
    ):
        """
        Replace `sign` field in params with random str if `sign` field exists in params
        """
        if with_signature:
            data = prepare_params(data, client.appid, client.apikey)
        # set to random value
        if data is not None and "sign" in data:
            data["sign"] = random_str(100)
        return post_method(self, url, data=data, with_signature=with_signature, **kwargs)

    mock = MonkeyPatch()
    mock.setattr(Session, "post", mock_post)
    with pytest.raises(InvalidParamException):
        client.create_key(
            keyspec=KeySpec.EH_AES_GCM_256,
            origin=Origin.EH_INTERNAL_KEY,
            keyusage=KeyUsage.EH_KEYUSAGE_SIGN_VERIFY,
        )
    mock.undo()
