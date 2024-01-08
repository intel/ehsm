from typing import Optional

from ehsm.session import Session

from ehsm.api.key_management import KeyManagementMixin
from ehsm.api.remote_attestation import RemoteAttestationMixin
from ehsm.api.crypto import CryptoMixin
from ehsm.api.secret_management import SecretManagementMixin
from ehsm.api.base import EHSMBaseClient


class Client(
    KeyManagementMixin,
    RemoteAttestationMixin,
    CryptoMixin,
    SecretManagementMixin,
    EHSMBaseClient,
):
    def __init__(
        self,
        base_url: str,
        *,
        session: Optional[Session] = None,
        appid: str = "",
        apikey: str = "",
        allow_insecure: bool = False,
    ) -> None:
        """
        Initialize APIClient for EHSM KMS service
        """
        if session:
            self._session = session
        else:
            self._session = Session(
                base_url, appid=appid, apikey=apikey, allow_insecure=allow_insecure
            )
        # store props
        self._allow_insecure = allow_insecure

    @property
    def base_url(self):
        return self._session.base_url

    @property
    def allow_insecure(self):
        return self._allow_insecure
