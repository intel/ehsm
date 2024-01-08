from typing import List, Optional
from pydantic import Field
from pydantic.dataclasses import dataclass

from ehsm.serializers.base import EHSMBase


@dataclass
class CreateSecretResponse(EHSMBase):
    pass


@dataclass
class UpdateSecretDescResponse(EHSMBase):
    pass


@dataclass
class PutSecretValueResponse(EHSMBase):
    pass


@dataclass
class SecretValueVersion:
    version_id: int = Field(alias="versionId")
    create_time: int = Field(alias="createTime")


@dataclass
class ListSecretVersionIdsResponse(EHSMBase):
    secret_name: str = Field(alias="secretName")
    total_count: int = Field(alias="totalCount")
    version_ids: List[SecretValueVersion] = Field(alias="versionIds")


@dataclass
class Secret:
    secret_name: str = Field(alias="secretName")
    create_time: int = Field(alias="createTime")
    description: Optional[str] = None


@dataclass
class ListSecretsResponse(EHSMBase):
    total_count: int = Field(alias="totalCount")
    secret_list: List[Secret] = Field(alias="secretList")


@dataclass
class DescribeSecretResponse(EHSMBase):
    description: str
    secret_name: str = Field(alias="secretName")
    create_time: int = Field(alias="createTime")
    planned_delete_time: int = Field(alias="plannedDeleteTime")
    rational_interval: str = Field(alias="rationalInterval")
    last_rotation_date: int = Field(alias="lastRotationDate")
    next_rotation_date: int = Field(alias="nextRotationDate")


@dataclass
class DeleteSecretResponse(EHSMBase):
    pass


@dataclass
class GetSecretValueResponse(EHSMBase):
    secret_name: str = Field(alias="secretName")
    secret_data: str = Field(alias="secretData")
    version_id: int = Field(alias="versionId")
    create_time: int = Field(alias="createTime")


@dataclass
class RestoreSecretResponse(EHSMBase):
    pass
