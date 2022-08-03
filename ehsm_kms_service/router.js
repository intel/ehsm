const { ehsm_keySpec_t, ehsm_keyorigin_t } = require('./ehsm_kms_params.js')
const {
  cryptographic_apis,
  enroll_apis,
  key_management_apis,
  secret_manager_apis,
  remote_attestation_apis,
  common_apis,
} = require('./apis')
const logger = require('./logger')
const {
  napi_result,
  _result,
  create_user_info,
  enroll_user_info,
  store_cmk,
  gen_hmac,
} = require('./function')
const {
  listKey,
  deleteALLKey,
  deleteKey,
  enableKey,
  disableKey,
} = require('./key_management_apis')
const {
  createSecret,
  putSecretValue
} = require('./secret_manager_apis')
/**
 *
 * @param {string} id (keyid|ukeyid)
 * @returns query (keyid|ukeyid) parameter
 *
 */
const cmk_db_query = (id) => {
  return {
    selector: {
      _id: `cmk:${id}`,
    },
    fields: ['keyBlob', 'creator', 'expireTime', 'keyState'],
    limit: 1,
  }
}
/**
 * Verify whether the request parameter appid is equal to creator in the database .
 * Verify expireTime , the expiration time cannot be less than the current time
 * @param {string} appid
 * @param {string} keyid
 * @param {object} res
 * @param {object} DB
 * @returns cmk_base64
 */
const find_cmk_by_keyid = async (appid, keyid, res, DB) => {
  const query = cmk_db_query(keyid)
  const cmk = await DB.partitionedFind('cmk', query)
  if (cmk.docs.length == 0) {
    res.send(_result(400, 'keyid error'))
    return false
  }
  const { keyBlob, creator, expireTime, keyState } = cmk.docs[0]
  if (appid != creator) {
    res.send(_result(400, 'appid error'))
    return false
  }
  if (keyState == 0 && keyState != null && keyState != undefined) {
    res.send(_result(400, 'keyid is disabled'))
    return false
  }
  if (new Date().getTime() > expireTime) {
    res.send(_result(400, 'keyid expire'))
    return
  }
  return keyBlob
}

const GetRouter = async (p) => {
  const { req, res, DB } = p
  const action = req.query.Action
  switch (action) {
    case common_apis.GetVersion:
      napi_res = napi_result(action, res, [])
      napi_res && res.send(napi_res)
      break;
    case enroll_apis.Enroll:
      enroll_user_info(action, DB, res, req)
      break;
    default:
      res.send(_result(404, 'Not Found', {}))
      break
  }
}

const router = async (p) => {
  const { req, res, DB } = p
  const { appid, payload } = req.body
  const action = req.query.Action
  switch (action) {
    case enroll_apis.RA_GET_API_KEY:
      create_user_info(action, DB, res, req)
      break
    case cryptographic_apis.CreateKey:
      try {
        let { keyspec, origin } = payload
        /**
         * keyspec、origin convert to enum type
         * enum in thie ehsm_kms_params.js file
         */
        keyspec = ehsm_keySpec_t[keyspec]
        origin = ehsm_keyorigin_t[origin]
        const napi_res = napi_result(action, res, [keyspec, origin])
        napi_res && store_cmk(napi_res, res, appid, payload, DB)
      } catch (error) {}
      break
    case cryptographic_apis.Encrypt:
      try {
        const { keyid, plaintext, aad = '' } = payload
        const cmk_base64 = await find_cmk_by_keyid(appid, keyid, res, DB)
        const napi_res = napi_result(action, res, [cmk_base64, plaintext, aad])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case cryptographic_apis.Decrypt:
      try {
        const { keyid, ciphertext, aad = '' } = payload
        const cmk_base64 = await find_cmk_by_keyid(appid, keyid, res, DB)
        napi_res = napi_result(action, res, [cmk_base64, ciphertext, aad])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case cryptographic_apis.GenerateDataKey:
      try {
        const { keyid, keylen, aad = '' } = payload
        const cmk_base64 = await find_cmk_by_keyid(appid, keyid, res, DB)
        napi_res = napi_result(action, res, [cmk_base64, keylen, aad])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case cryptographic_apis.GenerateDataKeyWithoutPlaintext:
      try {
        const { keyid, keylen, aad = '' } = payload
        const cmk_base64 = await find_cmk_by_keyid(appid, keyid, res, DB)
        napi_res = napi_result(action, res, [cmk_base64, keylen, aad])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case cryptographic_apis.Sign:
      try {
        const { keyid, digest } = payload
        const cmk_base64 = await find_cmk_by_keyid(appid, keyid, res, DB)
        napi_res = napi_result(action, res, [cmk_base64, digest])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case cryptographic_apis.Verify:
      try {
        const { keyid, digest, signature } = payload
        const cmk_base64 = await find_cmk_by_keyid(appid, keyid, res, DB)
        napi_res = napi_result(action, res, [
          cmk_base64,
          digest,
          signature,
        ])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case cryptographic_apis.AsymmetricEncrypt:
      try {
        const { keyid, plaintext } = payload
        const cmk_base64 = await find_cmk_by_keyid(appid, keyid, res, DB)
        napi_res = napi_result(action, res, [cmk_base64, plaintext])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case cryptographic_apis.AsymmetricDecrypt:
      try {
        const { keyid, ciphertext } = payload
        const cmk_base64 = await find_cmk_by_keyid(appid, keyid, res, DB)
        napi_res = napi_result(action, res, [cmk_base64, ciphertext])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case cryptographic_apis.ExportDataKey:
      try {
        const { keyid, ukeyid, aad = '', olddatakey_base } = payload
        const cmk_base64 = await find_cmk_by_keyid(appid, keyid, res, DB)
        const ukey_base64 = await find_cmk_by_keyid(appid, ukeyid, res, DB)
        napi_res = napi_result(action, res, [
          cmk_base64,
          ukey_base64,
          aad,
          olddatakey_base,
        ])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case enroll_apis.RA_HANDSHAKE_MSG0:
      try {
        const json_str_params = JSON.stringify({ ...req.body })
        napi_res = napi_result(action, res, [json_str_params])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case enroll_apis.RA_HANDSHAKE_MSG2:
      try {
        const json_str_params = JSON.stringify({ ...req.body })
        napi_res = napi_result(action, res, [json_str_params])
        napi_res && res.send(napi_res)
      } catch (error) {}
      break
    case key_management_apis.ListKey:
      listKey(appid, res, DB)
      break
    case key_management_apis.DeleteKey:
      deleteKey(appid, payload, res, DB)
      break
    case key_management_apis.DeleteAllKey:
      deleteALLKey(appid, res, DB)
      break
    case key_management_apis.EnableKey:
      enableKey(appid, payload, res, DB)
      break
    case key_management_apis.DisableKey:
      disableKey(appid, payload, res, DB)
      break
    case remote_attestation_apis.GenerateQuote:
      try {
        const { challenge } = payload
        if (challenge) {
          napi_res = napi_result(action, res, [challenge])
          napi_res && res.send(napi_res)
        } else {
          res.send(_result(400, 'Empty challenge', {}))
        }
      } catch (error) {}
      break
    case remote_attestation_apis.VerifyQuote:
      try {
        const { quote, nonce } = payload
        if (quote && nonce) {
          napi_res = napi_result(action, res, [quote, nonce])
          if (napi_res) {
            let {error, hmac} = await gen_hmac(DB, appid, napi_res.result)
            if (hmac.length > 0) {
              napi_res.result.sign = hmac
              res.send(napi_res)
            } else {
              res.send(_result(400, 'Internal error', {}))
            }
          } else {
            res.send(_result(400, 'Empty quote or nonce ', {}))
          }
        }
      } catch (error) {}
      break
    case secret_manager_apis.CreateSecret:
        createSecret(res, appid, payload, DB)
      break
    case secret_manager_apis.PutSecretValue:
        putSecretValue(res, appid, payload, DB)
      break
    default:
      res.send(_result(404, 'API Not Found', {}))
      break
  }
}
module.exports = {
  router,
  GetRouter
}
