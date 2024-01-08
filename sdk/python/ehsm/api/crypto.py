from ehsm.serializers.crypto import *
from ehsm.api.enums import *
from ehsm.api.base import EHSMBaseClient


class CryptoMixin(EHSMBaseClient):
    def create_key(self, keyspec: KeySpec, origin: Origin, keyusage: KeyUsage):
        resp = self._session.post(
            "",
            params={"Action": "CreateKey"},
            data={"keyspec": keyspec, "origin": origin, "keyusage": keyusage},
        )
        return CreateKeyResponse.from_response(resp)

    def encrypt(self, aad: str, keyid: str, plaintext: str):
        resp = self._session.post(
            "",
            params={"Action": "Encrypt"},
            data={"aad": aad, "keyid": keyid, "plaintext": plaintext},
        )
        return EncryptResponse.from_response(resp)

    def decrypt(self, aad: str, keyid: str, ciphertext: str):
        resp = self._session.post(
            "",
            params={"Action": "Decrypt"},
            data={"aad": aad, "keyid": keyid, "ciphertext": ciphertext},
        )
        return DecryptResponse.from_response(resp)

    def asymm_encrypt(self, keyid: str, plaintext: str, padding_mode: PaddingMode):
        resp = self._session.post(
            "",
            params={"Action": "AsymmetricEncrypt"},
            data={"keyid": keyid, "plaintext": plaintext, "padding_mode": padding_mode},
        )
        return AsymmetricEncryptResponse.from_response(resp)

    def asymm_decrypt(self, keyid: str, ciphertext: str, padding_mode: PaddingMode):
        resp = self._session.post(
            "",
            params={"Action": "AsymmetricDecrypt"},
            data={
                "keyid": keyid,
                "ciphertext": ciphertext,
                "padding_mode": padding_mode,
            },
        )
        return AsymmetricDecryptResponse.from_response(resp)

    def sign(
        self,
        keyid: str,
        padding_mode: PaddingMode,
        digest_mode: DigestMode,
        message_type: MessageType,
        message: str,
    ):
        resp = self._session.post(
            "",
            params={"Action": "Sign"},
            data={
                "keyid": keyid,
                "padding_mode": padding_mode,
                "digest_mode": digest_mode,
                "message_type": message_type,
                "message": message,
            },
        )
        return SignResponse.from_response(resp)

    def verify(
        self,
        keyid: str,
        padding_mode: PaddingMode,
        digest_mode: DigestMode,
        message_type: MessageType,
        message: str,
        signature: str,
    ):
        resp = self._session.post(
            "",
            params={"Action": "Verify"},
            data={
                "keyid": keyid,
                "padding_mode": padding_mode,
                "digest_mode": digest_mode,
                "message_type": message_type,
                "message": message,
                "signature": signature,
            },
        )
        return VerifyResponse.from_response(resp)

    def generate_data_key(self, aad: str, keyid: str, keylen: int):
        resp = self._session.post(
            "",
            params={"Action": "GenerateDataKey"},
            data={
                "keylen": keylen,
                "keyid": keyid,
                "aad": aad,
            },
        )
        return GenerateDataKeyResponse.from_response(resp)

    def generate_data_key_without_plaintext(self, aad: str, keyid: str, keylen: int):
        resp = self._session.post(
            "",
            params={"Action": "GenerateDataKeyWithoutPlaintext"},
            data={"aad": aad, "keyid": keyid, "keylen": keylen},
        )
        return GenerateDataKeyWithoutPlaintextResponse.from_response(resp)

    def export_data_key(
        self,
        aad: str,
        keyid: str,
        old_data_key: str,
        ukeyid: str,
        padding_mode: PaddingMode,
    ):
        resp = self._session.post(
            "",
            params={"Action": "ExportDataKey"},
            data={
                "aad": aad,
                "keyid": keyid,
                "old_data_key": old_data_key,
                "ukeyid": ukeyid,
                "padding_mode": padding_mode,
            },
        )
        return ExportDataKeyResponse.from_response(resp)

    def get_public_key(self, keyid: str):
        resp = self._session.post(
            "", params={"Action": "GetPublicKey"}, data={"keyid": keyid}
        )
        return GetPublicKeyResponse.from_response(resp)

    def import_key_material(
        self, keyid: str, key_material: str, padding_mode: PaddingMode, importToken: str
    ):
        resp = self._session.post(
            "",
            params={"Action": "ImportKeyMaterial"},
            data={
                "keyid": keyid,
                "key_material": key_material,
                "padding_mode": padding_mode,
                "importToken": importToken,
            },
        )
        return ImportKeyMaterialResponse.from_response(resp)

    def get_parameters_for_import(self, keyid: str, keyspec: KeySpec):
        resp = self._session.post(
            "",
            params={"Action": "GetParametersForImport"},
            data={
                "keyid": keyid,
                "keyspec": keyspec,
            },
        )
        return GetParamtersForImportResponse.from_response(resp)
