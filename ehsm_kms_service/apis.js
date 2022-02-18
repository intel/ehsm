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
}

const key_management_apis = {
  ListKey: 'ListKey',
  DeleteKey: 'DeleteKey',
  DeleteAllKey: 'DeleteAllKey',
  EnableKey: 'EnableKey',
  DisableKey: 'DisableKey',
}
module.exports = { cryptographic_apis, enroll_apis, key_management_apis }
