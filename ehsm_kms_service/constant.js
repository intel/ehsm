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
  EH_AES_GCM_128: 0,
  EH_AES_GCM_192: 1,
  EH_AES_GCM_256: 2,
  EH_RSA_2048: 3,
  EH_RSA_3072: 4,
  EH_RSA_4096: 5,
  EH_EC_P224: 6,
  EH_EC_P256: 7,
  EH_EC_P384: 8,
  EH_EC_P512: 9,
  EH_HMAC: 10,
  EH_SM2: 11,
  EH_SM3: 12,
  EH_SM: 13
}
const ehsm_keyorigin_t = {
  EH_INTERNAL_KEY: 0,
  EXTERNAL_KEY: 1
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
  ehsm_action_t
}
