# eHSM Python SDK

> The python SDK is still under active development and not available for production yet

## Dependencies

- Python 3.8 or above
- [httpx](https://www.python-httpx.org/) - A next-generation HTTP client for Python.
- [marshmallow](https://marshmallow.readthedocs.io/en/stable/) - simplified object serialization

## Usage

TBA

## Supported APIs

The python SDK is under active development and plans to support all [eHSM APIs](https://github.com/intel/ehsm/blob/main/docs/API_Reference.md). The supported API are marked as checked in the following API lists.

### Cryptographic Functionalities APIs

- [ ] CreateKey
- [ ] Encrypt
- [ ] Decrypt
- [ ] AsymmetricEncrypt
- [ ] AsymmetricDecrypt
- [ ] Sign
- [ ] Verify
- [ ] GenerateDataKey
- [ ] GenerateDataKeyWithoutPlaintext
- [ ] ExportDataKey
- [ ] GetPublicKey

### Key Management APIs

- [ ] GetVersion
- [ ] Enroll
- [ ] ListKey
- [ ] DeleteKey
- [ ] DeleteALLKey
- [ ] EnableKey
- [ ] DisableKey

### Remote Attestation APIs

- [ ] GenerateQuote
- [ ] VerifyQuote
- [ ] UploadQuotePolicy
- [ ] GetQuotePolicy

### Secret Manager APIs

- [ ] CreateSecret
- [ ] UpdateSecretDesc
- [ ] PutSecretValue
- [ ] ListSecretVersionIds
- [ ] ListSecrets
- [ ] DescribeSecret
- [ ] DeleteSecret
- [ ] GetSecretValue
- [ ] RestoreSecret
