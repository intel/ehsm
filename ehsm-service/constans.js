const pramas = {
  CreateKey: {
    mechanism: {
      type : 'string',
      maxLength: 128,
      length: 100
    },
    origin: {
      type: 'string',
      maxLength: 128,
      length: 100
    }
  },
  Encrypt: {
    mechanism: {
      type : 'string',
      maxLength: 128,
      length: 100
    },
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
    mechanism: {
      type : 'string',
      maxLength: 128,
      length: 100
    },
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
  GenerateDataKey: {
    mechanism: {
      type : 'string',
      maxLength: 128,
      length: 100
    },
    masterKey: {
      type: 'string',
      maxLength: 128,
      length: 100
    }
  },
  GenerateDataKeyWithoutPlaintext: {
    mechanism: {
      type : 'string',
      maxLength: 128,
      length: 100
    },
    masterKey: {
      type: 'string',
      maxLength: 128,
      length: 100
    }
  },
  ExportDataKey: {
    mechanism: {
      type : 'string',
      maxLength: 128,
      length: 100
    },
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
    mechanism: {
      type : 'string',
      maxLength: 128,
      length: 100
    },
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
    mechanism: {
      type : 'string',
      maxLength: 128,
      length: 100
    },
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