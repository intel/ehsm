const MAX_LENGTH = 6 * 1024
const { ehsm_keySpec_t, ehsm_keyorigin_t, ehsm_message_type_t, ehsm_digest_mode_t, ehsm_padding_mode_t } = require('./constant')
const { KMS_ACTION } = require('./apis')
const { _result } = require('./function')
const logger = require('./logger')

const is_base64 = (base64_str) => {
  if (base64_str == undefined ||
    typeof base64_str != 'string' ||
    base64_str.length == 0 ||
    (base64_str.length % 4) != 0) {
    return false
  }
  return /^[a-zA-Z0-9\+\/]+(\={0,2})$/gi.test(base64_str)
}

const PARAM_DATA_TYPE = {
  STRING: 'string',
  BASE64: 'base64',
  INT: 'int',
  CONST: 'const'
}

const message_type = {
  type: PARAM_DATA_TYPE.CONST,
  arr: Object.keys(ehsm_message_type_t),
  required: true,
}

const digest_mode = {
  type: PARAM_DATA_TYPE.CONST,
  arr: Object.keys(ehsm_digest_mode_t),
  required: true,
}

const padding_mode = {
  type: PARAM_DATA_TYPE.CONST,
  arr: Object.keys(ehsm_padding_mode_t),
  required: true,
}

const keyid = {
  type: PARAM_DATA_TYPE.STRING,
  minLength: 36,
  maxLength: 36,
  required: true,
  regex: /^([a-z\d]{8}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{12})$/,
  regex_err_msg: 'format wrong'
}
const aad = {
  type: PARAM_DATA_TYPE.BASE64,
  maxLength: MAX_LENGTH * 4 / 3,  // This is the length after base64 encoding.
  required: false,
}

// params format
const cryptographic_params = {
  [KMS_ACTION.cryptographic.CreateKey]: {
    keyspec: {
      type: PARAM_DATA_TYPE.CONST,
      arr: Object.keys(ehsm_keySpec_t),
      required: true,
    },
    origin: {
      type: PARAM_DATA_TYPE.CONST,
      arr: Object.keys(ehsm_keyorigin_t),
      required: true,
    },
  },
  [KMS_ACTION.cryptographic.Encrypt]: {
    keyid,
    plaintext: {
      type: PARAM_DATA_TYPE.BASE64,
      maxLength: MAX_LENGTH * 4 / 3,  // This is the length after base64 encoding.
      minLength: 1,
      required: true,
    },
    aad,
  },
  [KMS_ACTION.cryptographic.Decrypt]: {
    keyid,
    ciphertext: {
      type: PARAM_DATA_TYPE.BASE64,
      maxLength: (MAX_LENGTH + 30) * 4 / 3,  // This is the length after base64 encoding. 
                                             // 30 is the length of base64(12B IV + 16B MAC), coming from ceil(28/3).
      minLength: 1,
      required: true,
    },
    aad,
  },
  [KMS_ACTION.cryptographic.GenerateDataKey]: {
    keyid,
    keylen: {
      type: PARAM_DATA_TYPE.INT,
      maxNum: 1024,
      minNum: 1,
      required: true,
    },
    aad,
  },
  [KMS_ACTION.cryptographic.GenerateDataKeyWithoutPlaintext]: {
    keyid,
    keylen: {
      type: PARAM_DATA_TYPE.INT,
      maxNum: 1024,
      minNum: 1,
      required: true,
    },
    aad,
  },
  [KMS_ACTION.cryptographic.Sign]: {
    keyid,
    message: {
      type: PARAM_DATA_TYPE.BASE64,
      maxLength: MAX_LENGTH * 4 / 3,  // This is the length after base64 encoding.
      minLength: 1,
      required: true,
    },
    message_type,
    digest_mode,
    padding_mode,
  },
  [KMS_ACTION.cryptographic.Verify]: {
    keyid,
    message: {
      type: PARAM_DATA_TYPE.BASE64,
      maxLength: MAX_LENGTH * 4 / 3,  // This is the length after base64 encoding.
      minLength: 1,
      required: true,
    },
    message_type,
    digest_mode,
    padding_mode,
    signature: {
      type: PARAM_DATA_TYPE.BASE64,
      maxLength: MAX_LENGTH * 4 / 3,  // This is the length after base64 encoding.
      minLength: 1,
      required: true,
    },
  },
  [KMS_ACTION.cryptographic.AsymmetricEncrypt]: {
    keyid,
    plaintext: {
      type: PARAM_DATA_TYPE.BASE64,
      maxLength: MAX_LENGTH * 4 / 3,  // This is the length after base64 encoding.
      minLength: 1,
      required: true,
    },
    padding_mode,
  },
  [KMS_ACTION.cryptographic.GetPublicKey]: {
    keyid,
  },
  [KMS_ACTION.cryptographic.GetParametersForImport]: {
    keyid,
    keyspec: {
      type: PARAM_DATA_TYPE.CONST,
      arr: Object.keys(ehsm_keySpec_t),
      required: true,
    },
  },
  [KMS_ACTION.cryptographic.ImportKeyMaterial]: {
    keyid,
    padding_mode,
    key_material: {
      type: PARAM_DATA_TYPE.BASE64,
      maxLength: MAX_LENGTH * 4 / 3,  // This is the length after base64 encoding.
      minLength: 1,
      required: true,
    },
  },
  [KMS_ACTION.cryptographic.AsymmetricDecrypt]: {
    keyid,
    ciphertext: {
      type: PARAM_DATA_TYPE.BASE64,
      maxLength: MAX_LENGTH * 4 / 3,  // This is the length after base64 encoding.
      minLength: 1,
      required: true,
    },
    padding_mode,
  },
  [KMS_ACTION.cryptographic.ExportDataKey]: {
    keyid,
    ukeyid: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: MAX_LENGTH * 4 / 3,  // This is the length after base64 encoding.
      required: true,
    },
    aad,
    olddatakey_base: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: MAX_LENGTH * 4 / 3,  // This is the length after base64 encoding.
      required: true,
    },
  },
}

const key_management_params = {
  [KMS_ACTION.key_management.ListKey]: {},
  [KMS_ACTION.key_management.DeleteKey]: {
    keyid
  },
  [KMS_ACTION.key_management.DeleteAllKey]: {},
  [KMS_ACTION.key_management.EnableKey]: {
    keyid
  },
  [KMS_ACTION.key_management.DisableKey]: {
    keyid
  }
}

const remote_attestation_params = {
  [KMS_ACTION.remote_attestation.GenerateQuote]: {
    challenge: {
      type: PARAM_DATA_TYPE.BASE64,
      minLength: 1,
      maxLength: 4 * 1024,
      required: true,
    }
  },
  [KMS_ACTION.remote_attestation.VerifyQuote]: {
    quote: {
      type: PARAM_DATA_TYPE.BASE64,
      maxLength: 10924, // the length after 8K base64
      minLength: 1,
      required: true,
    },
    nonce: {
      type: PARAM_DATA_TYPE.BASE64,
      maxLength: 4 * 1024,
      minLength: 1,
      required: true,
    },
    policyId: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 36,
      maxLength: 36,
      required: false,
      regex: /^([a-z\d]{8}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{12})$/,
      regex_err_msg: 'format wrong'
    }
  },
  [KMS_ACTION.remote_attestation.UploadQuotePolicy]: {
    mr_enclave: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 64,
      maxLength: 64,
      required: true
    },
    mr_signer: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 64,
      maxLength: 64,
      required: true
    }
  },
  [KMS_ACTION.remote_attestation.GetQuotePolicy]: {
    policyId: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 36,
      maxLength: 36,
      required: true,
      regex: /^([a-z\d]{8}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{12})$/,
      regex_err_msg: 'format wrong'
    }
  }
}

const secret_manager_params = {
  [KMS_ACTION.secret_manager.CreateSecret]: {
    secretName: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 64,
      required: true
    },
    secretData: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 4096,
      required: true
    },
    encryptionKeyId: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 36,
      maxLength: 36,
      required: false,
      regex: /^([a-z\d]{8}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{12})$/,
      regex_err_msg: 'format wrong'
    },
    description: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 0,
      maxLength: 4096,
      required: false
    },
    rotationInterval: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 0,
      maxLength: 5,
      required: false,
      regex: /^(\d{1,4}[d,h,m,s]{1})$/,
      regex_err_msg: 'format wrong'
    }
  },
  [KMS_ACTION.secret_manager.UpdateSecretDesc]: {
    secretName: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 64,
      required: true
    },
    description: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 0,
      maxLength: 4096,
      required: false
    }
  },
  [KMS_ACTION.secret_manager.PutSecretValue]: {
    secretName: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 64,
      required: true
    },
    secretData: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 4096,
      required: true
    }
  },
  [KMS_ACTION.secret_manager.ListSecretVersionIds]: {
    secretName: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 64,
      required: true
    }
  },
  [KMS_ACTION.secret_manager.ListSecrets]: {
    secretName: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 64,
      required: false
    }
  },
  [KMS_ACTION.secret_manager.DescribeSecret]: {
    secretName: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 64,
      required: true
    }
  },
  [KMS_ACTION.secret_manager.DeleteSecret]: {
    secretName: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 64,
      required: true
    },
    recoveryPeriod: {
      type: PARAM_DATA_TYPE.INT,
      minNum: 1,
      maxNum: 365,
      required: false
    },
    forceDelete: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 0,
      maxLength: 5,
      required: false
    }
  },
  [KMS_ACTION.secret_manager.GetSecretValue]: {
    secretName: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 64,
      required: true
    },
    versionId: {
      type: PARAM_DATA_TYPE.INT,
      minNum: 1,
      required: false
    }
  },
  [KMS_ACTION.secret_manager.RestoreSecret]: {
    secretName: {
      type: PARAM_DATA_TYPE.STRING,
      minLength: 1,
      maxLength: 64,
      required: true
    }
  }
}


/**
 * Verify each parameter in the payload, such as data type,
 * data length, whether it is the specified value,
 * whether it is required, etc.
 * For parameter description, see <params_format.js>
 * @param {object} req
 * @param {object} res
 * @returns true | false
 */
const checkPayload = function (req, res) {
  try {
    const action = req.query.Action
    const { payload } = req.body
    if (payload == undefined) {
      return true
    }
    let current_payload_params_format = {}
    // check cryptographic parameter
    if (action === KMS_ACTION.cryptographic[action]) {
      current_payload_params_format = cryptographic_params[action]
    } else if (action === KMS_ACTION.key_management[action]) {
      current_payload_params_format = key_management_params[action]
    } else if (action === KMS_ACTION.remote_attestation[action]) {
      current_payload_params_format = remote_attestation_params[action]
    } else if (action === KMS_ACTION.secret_manager[action]) {
      current_payload_params_format = secret_manager_params[action]
    }

    for (const key in current_payload_params_format) {
      const format = current_payload_params_format[key];
      const value = payload[key];
      // check require
      if (format.required) {
        if (value == undefined || value === '') {
          res.send(_result(400, `Missing required parameters, The ${key} cannot be empty.`))
          return false
        }
      }
      // check by format type
      if (value != undefined && value !== '') {
        switch (format.type) {
          case PARAM_DATA_TYPE.STRING:
            // check type
            if (typeof value != 'string') {
              res.send(_result(400, `Parameter invalid, The ${key} must be of string type.`))
              return false
            }
            // check length
            if (format.maxLength != undefined && value.length > format.maxLength) {
              res.send(_result(400, `Parameter invalid, The ${key} length error.`))
              return false
            }
            if (format.minLength != undefined && value.length < format.minLength) {
              res.send(_result(400, `Parameter invalid, The ${key} length error.`))
              return false
            }
            if (format.regex != undefined) {
              if (!format.regex.test(value)) {
                res.send(_result(400, `Parameter invalid, The ${key} ${format.regex_err_msg != undefined ? format.regex_err_msg : 'format wrong'}.`))
                return false
              }
            }
            break;
          case PARAM_DATA_TYPE.BASE64:
            // check type
            if (typeof value != 'string') {
              res.send(_result(400, `Parameter invalid, The ${key} must be of string type.`))
              return false
            }
            // check length
            if (format.maxLength != undefined && value.length > format.maxLength) {
              res.send(_result(400, `Parameter invalid, The ${key} length error.`))
              return false
            }
            if (format.minLength != undefined && value.length < format.minLength) {
              res.send(_result(400, `Parameter invalid, The ${key} length error.`))
              return false
            }
            // check string is a base64 string
            if (!is_base64(value)) {
              res.send(_result(400, `Parameter invalid, The ${key} not a vailed base64 string.`))
              return false
            }
            break;
          case PARAM_DATA_TYPE.INT:
            // check type
            if (!Number.isInteger(value)) {
              res.send(_result(400, `Parameter invalid, The ${key} must be of integer type.`))
              return false
            }
            // must be a integer
            if (!(/^-?[0-9]*$/).test(value)) {
              res.send(_result(400, `Parameter invalid, The ${key} must be of integer type.`))
              return false
            }
            // check value between minNum and maxNum
            if (format.maxNum != undefined && value > format.maxNum) {
              res.send(_result(400, `Parameter invalid, The ${key} value must be less than or equal to ${format.maxNum}.`))
              return false
            }
            if (format.minNum != undefined && value < format.minNum) {
              res.send(_result(400, `Parameter invalid, The ${key} value must be greater than or equal to ${format.minNum}.`))
              return false
            }
            break;
          case PARAM_DATA_TYPE.CONST:
            if (!format.arr.includes(value)) {
              res.send(_result(400, `Parameter invalid, The ${key} type is incorrect.`))
              return false
            }
            break;
          default:
            logger.info(`checkPayload ::  Can't process the ${key}'s type [${format.type}].`)
            res.send(_result(500, 'Server internal error, please contact the administrator.'))
            return false
        }
      }
    }
    return true
  } catch (error) {
    logger.error(error)
    res.send(_result(500, 'Server internal error, please contact the administrator.'))
    return false
  }
}



module.exports = {
  checkPayload
}
