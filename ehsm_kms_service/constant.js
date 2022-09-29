const { KMS_ACTION } = require('./apis')
const Definition = {
  MAX_TIME_STAMP_DIFF: 10 * 60 * 1000,
  NONCE_CACHE_TIME: 10 * 60 * 1000 * 2, // MAX_TIME_STAMP_DIFF * 2
  TIMESTAMP_LEN: 13,
  CMK_EFFECTIVE_DURATION: 1 * 365 * 24 * 60 * 60 * 1000,
  CMK_LOOP_CLEAR_TIME: 24 * 60 * 60 * 1000,
  CMK_EXPIRE_TIME_EXPAND: 10 * 24 * 60 * 60 * 1000,
  CMK_LOOP_CLEAR_EXECUTION_TIME: 3,
  SM_SECRET_VERSION_STAGE_CURRENT: 1,
  SM_SECRET_VERSION_STAGE_PREVIOUS: 0,
  DEFAULT_DELETE_RECOVERY_DAYS: 30,
}

const ehsm_keySpec_t = {
  AES_GCM_128: 0,
  AES_GCM_192: 1,
  AES_GCM_256: 2,
  RSA_2048: 3,
  RSA_3072: 4,
  RSA_4096: 5,
  EC_P224: 6,
  EC_P256: 7,
  EC_P384: 8,
  EC_P512: 9,
  HMAC: 10,
  SM2: 11,
  SM4_CTR: 12,
  SM4_CBC: 13
}
const ehsm_keyorigin_t = {
  EH_INTERNAL_KEY: 0,
  EH_EXTERNAL_KEY: 1
}

const ehsm_paddingMode_t = {
  NO_PADDING: 0,
  PAD_RSA_PKCS1: 1,
  PAD_RSA_NO: 3,
  PAD_RSA_PKCS1_OAEP: 4,  
  PAD_RSA_PKCS1_PSS: 6
}

const ehsm_digestMode_t = {
  NONE: 0,
  SHA_2_224: 1,
  SHA_2_256: 2,
  SHA_2_384: 3,
  SHA_2_512: 4,
  SM3: 5
}

const ehsm_action_t = {
  EH_INITIALIZE: 0,
  EH_FINALIZE: 1,
  [KMS_ACTION.cryptographic.CreateKey]: 2,
  [KMS_ACTION.cryptographic.Encrypt]: 3,
  [KMS_ACTION.cryptographic.Decrypt]: 4,
  [KMS_ACTION.cryptographic.AsymmetricEncrypt]: 5,
  [KMS_ACTION.cryptographic.AsymmetricDecrypt]: 6,
  [KMS_ACTION.cryptographic.Sign]: 7,
  [KMS_ACTION.cryptographic.Verify]: 8,
  [KMS_ACTION.cryptographic.GenerateDataKey]: 9,
  [KMS_ACTION.cryptographic.GenerateDataKeyWithoutPlaintext]: 10,
  [KMS_ACTION.cryptographic.ExportDataKey]: 11,
  [KMS_ACTION.common.GetVersion]: 12,
  [KMS_ACTION.enroll.Enroll]: 13,
  [KMS_ACTION.remote_attestation.GenerateQuote]: 14,
  [KMS_ACTION.remote_attestation.VerifyQuote]: 15
}

module.exports = {
  Definition,
  ehsm_keySpec_t,
  ehsm_keyorigin_t,
  ehsm_action_t,
  ehsm_digestMode_t,
  ehsm_paddingMode_t
}
