from ehsm.serializers.base import EHSMResponse


def assert_response_success(resp: EHSMResponse):
    assert resp.code == 200
    assert "success" in resp.message.lower()
