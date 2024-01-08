from pydantic.dataclasses import dataclass
from pydantic import Field
from typing import List

from ehsm.serializers.base import EHSMBase


@dataclass
class GetVersionResponse(EHSMBase):
    version: str
    git_sha: str


@dataclass
class EnrollResponse(EHSMBase):
    appid: str
    apikey: str


@dataclass
class ListKeyItem:
    keyid: str
    alias: str
    keyspec: str
    keystate: int = Field(alias="keyState")
    creation_date: int = Field(alias="creationDate")
    expire_time: int = Field(alias="expireTime")


@dataclass
class ListKeyResponse(EHSMBase):
    list: List[ListKeyItem]


@dataclass
class DeleteKeyResponse(EHSMBase):
    pass


@dataclass
class DeleteAllKeyResponse(EHSMBase):
    pass


@dataclass
class EnableKeyResponse(EHSMBase):
    pass


@dataclass
class DisableKeyResponse(EHSMBase):
    pass
