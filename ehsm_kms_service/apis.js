const cryptographic = {
  CreateKey: 'CreateKey',
  Encrypt: 'Encrypt',
  Decrypt: 'Decrypt',
  GenerateDataKey: 'GenerateDataKey',
  GenerateDataKeyWithoutPlaintext: 'GenerateDataKeyWithoutPlaintext',
  Sign: 'Sign',
  Verify: 'Verify',
  AsymmetricEncrypt: 'AsymmetricEncrypt',
  AsymmetricDecrypt: 'AsymmetricDecrypt',
  ExportDataKey: 'ExportDataKey',
  GetPublicKey: 'GetPublicKey',
  ImportKeyMaterial: 'ImportKeyMaterial',
  GetParametersForImport: 'GetParametersForImport'
}

const enroll = {
  Enroll: 'Enroll',
}

const remote_attestation = {
  GenerateQuote: 'GenerateQuote',
  VerifyQuote: 'VerifyQuote',
  UploadQuotePolicy: 'UploadQuotePolicy',
  GetQuotePolicy: 'GetQuotePolicy'
}

const key_management = {
  ListKey: 'ListKey',
  DeleteKey: 'DeleteKey',
  DeleteAllKey: 'DeleteAllKey',
  EnableKey: 'EnableKey',
  DisableKey: 'DisableKey',
}

const secret_manager = {
  CreateSecret: 'CreateSecret',
  UpdateSecretDesc: 'UpdateSecretDesc',
  PutSecretValue: 'PutSecretValue',
  ListSecretVersionIds: 'ListSecretVersionIds',
  ListSecrets: 'ListSecrets',
  DescribeSecret: 'DescribeSecret',
  DeleteSecret: 'DeleteSecret',
  GetSecretValue: 'GetSecretValue',
  RestoreSecret: 'RestoreSecret'
}

const common = {
  GetVersion: 'GetVersion',
  GenHmac: 'GenHmac',
  GenTokenHmac: 'GenTokenHmac',
}

const KMS_ACTION = {
  cryptographic,
  enroll,
  key_management,
  remote_attestation,
  common,
  secret_manager
}

module.exports = {
  KMS_ACTION
}
