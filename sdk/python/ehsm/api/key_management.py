from ehsm.serializers.key_management import (
    GetVersionResponse,
    ListKeyResponse,
)
from .base import EHSMBaseClient


class KeyManagementMixin(EHSMBaseClient):

    def get_version(self):
        resp = self._session.get('', params={'Action': 'GetVersion'})
        return GetVersionResponse.from_response(resp)

    def enroll(self):
        return self._session.enroll()

    def list_key(self):
        resp = self._session.post('', params={'Action': 'ListKey'})
        return ListKeyResponse.from_response(resp)
