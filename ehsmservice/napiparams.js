const mechanism= {
  type : 'const',
  arr: ['EHM_AES_GCM_128','EHM_RSA_3072'],
  errortext: "mechanism is must 'EHM_AES_GCM_128' or 'EHM_RSA_3072'",
};
const pramas = {
  CreateKey: {
    mechanism,
    origin: {
      type : 'const',
      arr: ['EHO_INTERNAL_KEY','EHO_EXTERNAL_KEY'],
      errortext: "mechanism is must 'EHO_INTERNAL_KEY' or 'EHO_EXTERNAL_KEY'",
    }
  },
  Encrypt: {
    mechanism,
    key: {
      type: 'string',
      maxLength: 128,
      length: 100
    },
    data: {
      type: 'string',
      maxLength: 128,
      length: 100
    }
  },
  Decrypt: {
    mechanism,
    enData: {
      type: 'string',
      maxLength: 128,
      length: 100
    },
    key: {
      type: 'string',
      maxLength: 128,
      length: 100
    },
  },
  GenerateDataKey: {
    mechanism,
    masterKey: {
      type: 'string',
      maxLength: 128,
      length: 100
    }
  },
  GenerateDataKeyWithoutPlaintext: {
    mechanism,
    masterKey: {
      type: 'string',
      maxLength: 128,
      length: 100
    }
  },
  ExportDataKey: {
    mechanism,
    userKey: {
      type: 'string',
      maxLength: 128,
      length: 100
    },
    masterKey: {
      type: 'string',
      maxLength: 128,
      length: 100
    },
    enKey: {
      type: 'string',
      maxLength: 128,
      length: 100
    },
  },
  Sign: {
    mechanism,
    key: {
      type: 'string',
      maxLength: 128,
      length: 100
    },
    enData: {
      type: 'string',
      maxLength: 128,
      length: 100
    }
  },
  Verify: {
    mechanism,
    key: {
      type: 'string',
      maxLength: 128,
      length: 100
    },
    data: {
      type: 'string',
      maxLength: 128,
      length: 100
    },
    signature: {
      type: 'string',
      maxLength: 128,
      length: 100
    }
  },
}
module.exports = pramas;