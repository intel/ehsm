from pydantic.dataclasses import dataclass
from .base import EHSMBase


@dataclass
class GenerateQuoteResponse(EHSMBase):
    challenge: str
    quote: str


@dataclass
class VerifyQuoteResponse(EHSMBase):
    result: bool
    nonce: str
    mr_enclave: str
    mr_signer: str
    sign: str


@dataclass
class UploadQuotePolicy(EHSMBase):
    policyId: str


@dataclass
class GetQuotePolicy(EHSMBase):
    policyId: str
    mr_enclave: str
    mr_signer: str
