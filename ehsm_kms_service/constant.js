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
  KEYSPEC_NONE : 0,
  AES_GCM_128: 1,
  AES_GCM_192: 2,
  AES_GCM_256: 3,
  RSA_2048: 10,
  RSA_3072: 11,
  RSA_4096: 12,
  EC_P224: 20,
  EC_P256: 21,
  EC_P384: 22,
  EC_P521: 23,
  SM2: 30,
  SM4_CTR: 31,
  SM4_CBC: 32,
  HMAC: 40,
}
const ehsm_keyorigin_t = {
  EH_ORIGIN_NONE : 0,
  EH_INTERNAL_KEY : 1,
  EH_EXTERNAL_KEY : 2
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
