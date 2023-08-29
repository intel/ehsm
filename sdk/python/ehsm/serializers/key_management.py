from dataclasses import dataclass
from typing import List

from .base import EHSMBase


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
    creation_date: int
    expire_time: int
    alias: str
    keyspec: str
    keystate: int


@dataclass
class ListKeyResponse(EHSMBase):
    list: List[ListKeyItem]
