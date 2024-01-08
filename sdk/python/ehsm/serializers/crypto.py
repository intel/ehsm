from pydantic.dataclasses import dataclass

from ehsm.serializers.base import EHSMBase


@dataclass
class CreateKeyResponse(EHSMBase):
    keyid: str


@dataclass
class EncryptResponse(EHSMBase):
    ciphertext: str


@dataclass
class DecryptResponse(EHSMBase):
    plaintext: str


@dataclass
class AsymmetricEncryptResponse(EHSMBase):
    ciphertext: str


@dataclass
class AsymmetricDecryptResponse(EHSMBase):
    plaintext: str


@dataclass
class SignResponse(EHSMBase):
    signature: str


@dataclass
class VerifyResponse(EHSMBase):
    result: bool


@dataclass
class GenerateDataKeyResponse(EHSMBase):
    plaintext: str
    ciphertext: str


@dataclass
class GenerateDataKeyWithoutPlaintextResponse(EHSMBase):
    ciphertext: str


@dataclass
class ExportDataKeyResponse(EHSMBase):
    newdatakey: str


@dataclass
class GetPublicKeyResponse(EHSMBase):
    pubkey: str


@dataclass
class ImportKeyMaterialResponse(EHSMBase):
   result: bool


@dataclass
class GetParamtersForImportResponse(EHSMBase):
    pubkey: str
    importToken: str
