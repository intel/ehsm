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
  required: false,
}
const aad = {
  type: 'base64',
  maxLength: MAX_LENGTH,
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
    keyid: {
      ...keyid, 
      required: true
    },
    plaintext: {
      type: 'base64',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
    aad,
  },
  Decrypt: {
    keyid: {
      ...keyid, 
      required: true
    },
    ciphertext: {
      type: 'base64',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
    aad,
  },
  GenerateDataKey: {
    keyid: {
      ...keyid, 
      required: true
    },
    keylen: {
      type: 'int',
      maxNum: 1024,
      minNum: 1,
      required: true,
    },
    aad,
  },
  GenerateDataKeyWithoutPlaintext: {
    keyid: {
      ...keyid, 
      required: true
    },
    keylen: {
      type: 'int',
      maxNum: 1024,
      minNum: 1,
      required: true,
    },
    aad,
  },
  Sign: {
    keyid: {
      ...keyid, 
      required: true
    },
    digest: {
      type: 'base64',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  Verify: {
    keyid: {
      ...keyid, 
      required: true
    },
    digest: {
      type: 'base64',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
    signature: {
      type: 'base64',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  AsymmetricEncrypt: {
    keyid: {
      ...keyid, 
      required: true
    },
    plaintext: {
      type: 'base64',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  AsymmetricDecrypt: {
    keyid: {
      ...keyid, 
      required: true
    },
    ciphertext: {
      type: 'string',
      maxLength: MAX_LENGTH,
      minLength: 1,
      required: true,
    },
  },
  ExportDataKey: {
    keyid: {
      ...keyid, 
      required: true
    },
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
