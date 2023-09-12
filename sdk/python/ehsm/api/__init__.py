from typing import Optional

from ehsm.session import Session

from .key_management import KeyManagementMixin
from .base import EHSMBaseClient


class Client(KeyManagementMixin, EHSMBaseClient):
    def __init__(
        self,
        base_url: str,
        *,
        session: Optional[Session] = None,
        appid: str = "",
        apikey: str = "",
        allow_insecure: bool = False
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
