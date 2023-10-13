from pydantic import Field
from pydantic.dataclasses import dataclass
from ehsm.serializers.base import EHSMBase


@dataclass
class GenerateQuoteResponse(EHSMBase):
    challenge: str
    quote: str


@dataclass
class VerifyQuoteResponse(EHSMBase):
    result: int
    nonce: str


@dataclass
class UploadQuotePolicy(EHSMBase):
    policy_id: str = Field(alias="policyId")


@dataclass
class GetQuotePolicy(EHSMBase):
    mr_enclave: str
    mr_signer: str
    policy_id: str = Field(alias="policyId")
