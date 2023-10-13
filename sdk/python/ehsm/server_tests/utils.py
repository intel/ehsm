from string import printable
import random

from ehsm.serializers.base import EHSMResponse


def assert_response_success(resp: EHSMResponse):
    assert resp.code == 200
    assert "success" in resp.message.lower()


def random_str(length: int = 8) -> str:
    if length <= 0 or not isinstance(length, int):
        raise ValueError(f"length must be a positive integer, got {length}")
    return "".join(random.choices(printable, k=length))
