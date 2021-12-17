
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

const _6kb_length = 6 * 1024;
const aad = {
  type: 'string',
  maxLength: 32,
}
const ehsm_kms_params = {
  CreateKey: {
    keyspec: {
      type : 'const',
      arr: Object.keys(ehsm_keyspec_t),
      errortext: "The keyspec type is incorrect",
    },
    origin: {
      type : 'const',
      arr: Object.keys(ehsm_keyorigin_t),
      errortext: "The origin type is incorrect",
    }
  },
  Encrypt: {
    cmk_base64: {
      type: 'string',
      minLength: 1
    },
    plaintext: {
      type: 'string',
      maxLength: _6kb_length,
      minLength: 1
    },
    aad,
  },
  Decrypt: {
    cmk_base64: {
      type: 'string',
      minLength: 1
    },
    ciphertext: {
      type: 'string',
      maxLength: _6kb_length,
      minLength: 1
    },
    aad,
  },
  GenerateDataKey: {
    cmk_base64: {
      type: 'string',
      minLength: 1
    },
    keylen: {
      type: 'int',
      maxNum: 1024,
      minNum: 1
    },
    aad,
  },
  GenerateDataKeyWithoutPlaintext: {
    cmk_base64: {
      type: 'string',
      minLength: 1
    },
    keylen: {
      type: 'int',
      maxNum: 1024,
      minNum: 1
    },
    aad,
  },
  Sign: {
    cmk_base64: {
      type: 'string',
      minLength: 1
    },
    digest: {
      type: 'string',
      maxLength: _6kb_length,
      minLength: 1
    },
  },
  Verify: {
    cmk_base64: {
      type: 'string',
      minLength: 1
    },
    digest: {
      type: 'string',
      maxLength: _6kb_length,
      minLength: 1
    },
    signature_base64:{
      type: 'string',
      maxLength: _6kb_length,
      minLength: 1
    },
  },
  AsymmetricEncrypt: {
    cmk_base64: {
      type: 'string',
      minLength: 1
    },
    plaintext: {
      type: 'string',
      maxLength: 318,
      minLength: 1
    },
  },
  AsymmetricDecrypt: {
    cmk_base64: {
      type: 'string',
      minLength: 1
    },
    ciphertext_base64: {
      type: 'string',
      maxLength: 384,
      minLength: 1
    },
  }
}
module.exports = { ehsm_kms_params, ehsm_keyspec_t, ehsm_keyorigin_t };