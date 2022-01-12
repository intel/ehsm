const cryptographic_apis = {
  CreateKey: 'CreateKey',
  Encrypt: 'Encrypt',
  Decrypt: 'Decrypt',
  GenerateDataKey: 'GenerateDataKey',
  GenerateDataKeyWithoutPlaintext: 'GenerateDataKeyWithoutPlaintext',
  ExportDataKey: 'ExportDataKey',
  Sign: 'Sign',
  Verify: 'Verify',
  AsymmetricEncrypt: 'AsymmetricEncrypt',
  AsymmetricDecrypt: 'AsymmetricDecrypt',
}

const enroll_apis = {
  RA_GET_API_KEY: 'RA_GET_API_KEY',
  RA_HANDSHAKE_MSG0: 'RA_HANDSHAKE_MSG0',
}
module.exports = { cryptographic_apis, enroll_apis }
