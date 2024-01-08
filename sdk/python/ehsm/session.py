from typing import Dict, Optional
import httpx

from .serializers.key_management import EnrollResponse
from .exceptions import CredentialMissingException
from .utils import prepare_params


class BaseSession:
    """Base Session"""

    def get(self, *args, **kwargs):
        raise NotImplementedError

    def post(self, *args, **kwargs):
        raise NotImplementedError


class Session(BaseSession):
    """
    A eHSM session with enroll API, add signature(HMAC) to request before send.

    Usage::

        >>> import ehsm
        >>> s = ehsm.Session(base_url='https://127.0.0.1:9002')
        >>> s.enroll()
        >>> s.get()
    """

    _client: httpx.Client
    _appid: str  # a random string
    _apikey: str  # an UUID

    def __init__(
        self,
        base_url: str,
        *,
        appid: Optional[str] = None,
        apikey: Optional[str] = None,
        allow_insecure: bool = False,
    ) -> None:
        super().__init__()
        self._client = httpx.Client(base_url=base_url, verify=not allow_insecure)
        if appid is not None and apikey is not None:
            self._appid = appid
            self._apikey = apikey

    def request(
        self, method: str, url: str, *, check_creadentials: bool = True, **kwargs
    ):
        if check_creadentials and not (self._appid and self._apikey):
            raise CredentialMissingException(
                "Missing appid or apikey, please call enroll() first"
            )
        # todo: Request to set timeout to NONE in order to pass the BYOK test
        resp = self._client.request(method, url, timeout=None, **kwargs)
        resp.raise_for_status()
        return resp

    def get(self, url: str, *, check_credentials: bool = True, **kwargs):
        return self.request("GET", url, check_creadentials=check_credentials, **kwargs)

    def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        *,
        check_credentials: bool = True,  # check if session has appid and apikey
        with_signature: bool = True,  # whether add signature to the payload or not
        emit_none_value: bool = True,  # whether remove all key which has None value
        **kwargs,
    ):
        if emit_none_value and data is not None:
            data_items = filter(lambda it: it[1] is not None, data.items())
            data = {k: v for k, v in data_items}
        if with_signature:
            data = prepare_params(data, self._appid, self._apikey)
        return self.request(
            "POST", url, check_creadentials=check_credentials, json=data, **kwargs
        )

    def enroll(self):
        """
        Obtain a valid access keypair (APPID and APIKey) which is MUST before request the public cryptographic APIs.
        """
        resp = self._client.get("/", params={"Action": "Enroll"})
        data = EnrollResponse.from_response(resp)
        self._appid, self._apikey = data.appid, data.apikey
        return (self._appid, self._apikey)

    @property
    def base_url(self):
        return self._client.base_url

    @property
    def appid(self):
        return self._appid

    @property
    def apikey(self):
        return self._apikey

    def set_appid(self, appid: str):
        self._appid = appid

    def set_apikey(self, apikey: str):
        self._apikey = apikey
