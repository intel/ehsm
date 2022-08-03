const cryptographic_apis = {
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
}

const enroll_apis = {
  RA_GET_API_KEY: 'RA_GET_API_KEY',
  RA_HANDSHAKE_MSG0: 'RA_HANDSHAKE_MSG0',
  RA_HANDSHAKE_MSG2: 'RA_HANDSHAKE_MSG2',
  Enroll: 'Enroll',
}

const remote_attestation_apis = {
  GenerateQuote: 'GenerateQuote',
  VerifyQuote: 'VerifyQuote',
}

const key_management_apis = {
  ListKey: 'ListKey',
  DeleteKey: 'DeleteKey',
  DeleteAllKey: 'DeleteAllKey',
  EnableKey: 'EnableKey',
  DisableKey: 'DisableKey',
}

const secret_manager_apis = {
  CreateSecret: 'CreateSecret',
  PutSecretValue: 'PutSecretValue'
}

const common_apis = {
  GetVersion: 'GetVersion'
}
module.exports = {
  cryptographic_apis,
  enroll_apis,
  key_management_apis,
  remote_attestation_apis,
  common_apis,
  secret_manager_apis,
}
