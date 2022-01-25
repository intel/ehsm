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
  EXTERNAL_KEY: 1,
}

const MAX_LENGTH = 8192

const keyid = {
  type: 'string',
  minLength: 1,
  maxLength: MAX_LENGTH,
  required: true,
}
const aad = {
  type: 'string',
  maxLength: 32,
  required: false,
}

const ehsm_kms_params = {
  CreateKey: {
    keyspec: {
      type: 'const',
      arr: Object.keys(ehsm_keySpec_t),
      errortext: 'The keyspec type is incorrect',
      required: true,
    },
    origin: {
      type: 'const',
      arr: Object.keys(ehsm_keyorigin_t),
      errortext: 'The origin type is incorrect',
      required: true,
    },
  },
  Encrypt: {
    keyid,
    plaintext: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
    aad,
  },
  Decrypt: {
    keyid,
    ciphertext: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
    aad,
  },
  GenerateDataKey: {
    keyid,
    keylen: {
      type: 'int',
      maxNum: 1024,
      minNum: 1,
      required: true,
    },
    aad,
  },
  GenerateDataKeyWithoutPlaintext: {
    keyid,
    keylen: {
      type: 'int',
      maxNum: 1024,
      minNum: 1,
      required: true,
    },
    aad,
  },
  Sign: {
    keyid,
    digest: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  Verify: {
    keyid,
    digest: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
    signature_base64: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  AsymmetricEncrypt: {
    keyid,
    plaintext: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  AsymmetricDecrypt: {
    keyid,
    ciphertext_base64: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  ExportDataKey: {
    keyid,
    ukeyid: {
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

module.exports = {
  ehsm_kms_params,
  ehsm_keySpec_t,
  ehsm_keyorigin_t,
}
