from ehsm.session import Session


class EHSMBaseClient:
    _session: Session

    @property
    def appid(self):
        return self._session.appid

    @property
    def apikey(self):
        return self._session.apikey

    def set_appid(self, appid: str):
        self._session.set_appid(appid)

    def set_apikey(self, apikey: str):
        self._session.set_apikey(apikey)
