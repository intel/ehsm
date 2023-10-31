class CredentialMissingException(Exception):
    """Missing credentials (app_id or api_key) in a session"""


class InvalidParamException(Exception):
    """Invalid param when requesting to eHSM KMS service"""


class ServerExceptionException(Exception):
    """Server exception when requesting to eHSM KMS service"""


class UnknownException(Exception):
    """The repsonse contains a status code other than 200, 4XX and 5XX"""
