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
  EH_AES_GCM_256: 1,
  EH_RSA_2048: 2,
  EH_RSA_3072: 3,
  EH_EC_P256: 4,
  EH_EC_P512: 5,
  EH_EC_SM2: 6,
  EH_SM4: 7,
}
const ehsm_keyorigin_t = {
  EH_INTERNAL_KEY: 0,
  EXTERNAL_KEY: 1
}

module.exports = {
  Definition,
  ehsm_keySpec_t,
  ehsm_keyorigin_t
}
