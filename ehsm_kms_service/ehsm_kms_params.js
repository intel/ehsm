
const ehsm_keyspec_t = {
  EH_AES_GCM_128: 0,
  EH_AES_GCM_256: 1,
  EH_RSA_2048: 2,
  EH_RSA_3072:3,
  EH_EC_P256: 4,
  EH_EC_P512: 5,
  EH_EC_SM2: 6,
  EH_SM4: 7,
}
const ehsm_keyorigin_t = {
  EH_INTERNAL_KEY: 0,
  EXTERNAL_KEY: 1,
}

const MAX_LENGTH = 8192;

const cmk_base64 = {
  type: 'string',
  minLength: 1,
  maxLength: MAX_LENGTH,
  required: true,
}
const aad = {
  type: 'string',
  maxLength: 32,
  required: false
}

const ehsm_kms_params = {
  CreateKey: {
    keyspec: {
      type : 'const',
      arr: Object.keys(ehsm_keyspec_t),
      errortext: "The keyspec type is incorrect",
      required: true,
    },
    origin: {
      type : 'const',
      arr: Object.keys(ehsm_keyorigin_t),
      errortext: "The origin type is incorrect",
      required: true,
    }
  },
  Encrypt: {
    cmk_base64,
    plaintext: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
    aad,
  },
  Decrypt: {
    cmk_base64,
    ciphertext: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
    aad,
  },
  GenerateDataKey: {
    cmk_base64,
    keylen: {
      type: 'int',
      maxNum: 1024,
      minNum: 1,
      required: true,
    },
    aad,
  },
  GenerateDataKeyWithoutPlaintext: {
    cmk_base64,
    keylen: {
      type: 'int',
      maxNum: 1024,
      minNum: 1,
      required: true,
    },
    aad,
  },
  Sign: {
    cmk_base64,
    digest: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  Verify: {
    cmk_base64,
    digest: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
    signature_base64:{
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  AsymmetricEncrypt: {
    cmk_base64,
    plaintext: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  AsymmetricDecrypt: {
    cmk_base64,
    ciphertext_base64: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  ExportDataKey: {
    cmk_base64,
    ukey_base64: {
      type: 'string',
      minLength: 1,
      maxLength: MAX_LENGTH,
      required: true,
    },
    aad,
    olddatakey_base: {
      type: 'string',
      minLength: 1,
      maxLength: MAX_LENGTH,
      required: true,
    },
  },
}
module.exports = { ehsm_kms_params, ehsm_keyspec_t, ehsm_keyorigin_t };