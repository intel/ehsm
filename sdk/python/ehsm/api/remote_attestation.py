from ehsm.serializers.remote_attestation import *
from ehsm.api.base import EHSMBaseClient


class RemoteAttestationMixin(EHSMBaseClient):
    def generate_quote(self, challenge: str):
        """
        Generate a quote of the eHSM-KMS core enclave for user used to do the
        SGX DCAP Remote Attestation. User may send it to a remote reliable
        third party or directly send it to eHSM-KMS via VerifyQuote API to do
        the quote verification.
        """
        resp = self._session.post(
            "", params={"Action": "GenerateQuote"}, data={"challenge": challenge}
        )
        return GenerateQuoteResponse.from_response(resp)

    def verify_quote(self, quote: str, nonce: str, policy_id: str):
        """
        Users are expected already got a valid DCAP format QUOTE. And it could
        use this API to send it to eHSM-KMS to do a quote verification.
        """
        resp = self._session.post(
            "",
            params={"Action": "VerifyQuote"},
            data={"quote": quote, "nonce": nonce, "policyId": policy_id},
        )
        return VerifyQuoteResponse.from_response(resp)

    def upload_quote_policy(self, mr_enclave: str, mr_signer: str):
        """
        The UploadQuotePolicy Support uploading MRenclave and MRsigner and
        returning new policy_id.
        """
        resp = self._session.post(
            "",
            params={"Action": "UploadQuotePolicy"},
            data={"mr_enclave": mr_enclave, "mr_signer": mr_signer},
        )
        return UploadQuotePolicy.from_response(resp)

    def get_quote_policy(self, policy_id: str):
        """
        Query a quote policy information by policy_id.
        """
        resp = self._session.post(
            "",
            params={"Action": "GetQuotePolicy"},
            data={"policyId": policy_id},
        )
        return GetQuotePolicy.from_response(resp)
