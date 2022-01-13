const express = require('express')

const logger = require('./logger')
const { cryptographic_apis, enroll_apis } = require('./apis')
const ehsm_napi = require('./ehsm_napi')
const { ehsm_keyspec_t, ehsm_keyorigin_t } = require('./ehsm_kms_params.js')
const { getIPAdress, _checkParams, _result } = require('./function')
const { NONCE_CACHE_TIME } = require('./constant')
const couchDB = require('./couchdb')

const app = express()
app.use(express.json())

const PORT = process.argv.slice(2)[0] || 9000

/**
 * ehsm napi result
 * @param {function name} action
 * @param {} res
 * @param {NAPI_* function params} params
 * @returns
 */
const napi_result = (action, res, params) => {
  try {
    ehsm_napi[`NAPI_${action}`].async(...params, (err, napi_res) => {
      if (err) {
        res.send(_result(400, 'Parsing error'))
        return
      }
      res.send(napi_res)
    })
  } catch (e) {
    res.send(_result(400, 'Parsing error'))
  }
}

/**
 * test couchDB
 * @param {object} DB
 * @param {object} res
 */
const create_app_info = (DB, res) => {
  const appid = new Date().getTime() + ''
  DB.insert({ appid: appid, appkey: appid }, appid)
    .then((r) => {
      res.send(_result(200, 'successful', { appid: appid, appkey: appid }))
    })
    .catch((e) => {
      res.send(_result(400, 'create app info faild', e))
    })
}

const server = (DB) => {
  // Clear nonce cache for more than 15 minutes
  const nonce_database = {}
  const nonce_cache_timer = setInterval(() => {
    try {
      for (const appid in nonce_database) {
        let slice_index =
          nonce_database[appid] &&
          nonce_database[appid].findIndex((nonce_data) => {
            return (
              new Date().getTime() - nonce_data.nonce_timestamp >
              NONCE_CACHE_TIME
            )
          })
        if (slice_index > 0) {
          nonce_database[appid] = nonce_database[appid].slice(slice_index)
        }
        if (slice_index == 0) {
          delete nonce_database[appid]
        }
      }
    } catch (error) {
      res.send(_result(404, 'Not Fount', {}))
      logger.error(JSON.stringify(error))
    }
  }, NONCE_CACHE_TIME / 2)

  const NAPI_Initialize = ehsm_napi.NAPI_Initialize()
  if (JSON.parse(NAPI_Initialize)['code'] != 200) {
    console.log('service Initialize exception!')
    clearInterval(nonce_cache_timer)
    process.exit(0)
  }

  app.use((req, res, next) => _checkParams(req, res, next, nonce_database, DB))

  /**
   * router
   */
  app.post('/ehsm', function (req, res) {
    try {
      const PAYLOAD = req.body.payload
      // ACTION: request function name
      const ACTION = req.query.Action
      if (ACTION === cryptographic_apis.CreateKey) {
        /**
         * CreateKey
         */
        let { keyspec, origin } = PAYLOAD
        keyspec = ehsm_keyspec_t[keyspec]
        origin = ehsm_keyorigin_t[origin]
        napi_result(ACTION, res, [keyspec, origin])
      } else if (ACTION === cryptographic_apis.Encrypt) {
        /**
         * Encrypt
         */
        const { cmk_base64, plaintext, aad = '' } = PAYLOAD
        napi_result(ACTION, res, [cmk_base64, plaintext, aad])
      } else if (ACTION === cryptographic_apis.Decrypt) {
        /**
         * Decrypt
         */
        const { cmk_base64, ciphertext, aad = '' } = PAYLOAD
        napi_result(ACTION, res, [cmk_base64, ciphertext, aad])
      } else if (ACTION === cryptographic_apis.GenerateDataKey) {
        /**
         * GenerateDataKey
         */
        const { cmk_base64, keylen, aad = '' } = PAYLOAD
        napi_result(ACTION, res, [cmk_base64, keylen, aad])
      } else if (
        ACTION === cryptographic_apis.GenerateDataKeyWithoutPlaintext
      ) {
        /**
         * GenerateDataKeyWithoutPlaintext
         */
        const { cmk_base64, keylen, aad = '' } = PAYLOAD
        napi_result(ACTION, res, [cmk_base64, keylen, aad])
      } else if (ACTION === cryptographic_apis.Sign) {
        /**
         * Sign
         */
        const { cmk_base64, digest } = PAYLOAD
        napi_result(ACTION, res, [cmk_base64, digest])
      } else if (ACTION === cryptographic_apis.Verify) {
        /**
         * Verify
         */
        const { cmk_base64, digest, signature_base64 } = PAYLOAD
        napi_result(ACTION, res, [cmk_base64, digest, signature_base64])
      } else if (ACTION === cryptographic_apis.AsymmetricEncrypt) {
        /**
         * AsymmetricEncrypt
         */
        const { cmk_base64, plaintext } = PAYLOAD
        napi_result(ACTION, res, [cmk_base64, plaintext])
      } else if (ACTION === cryptographic_apis.AsymmetricDecrypt) {
        /**
         * AsymmetricDecrypt
         */
        const { cmk_base64, ciphertext_base64 } = PAYLOAD
        napi_result(ACTION, res, [cmk_base64, ciphertext_base64])
      } else if (ACTION === cryptographic_apis.ExportDataKey) {
        /**
         * ExportDataKey
         */
        const { cmk_base64, ukey_base64, aad = '', olddatakey_base } = PAYLOAD
        napi_result(ACTION, res, [
          cmk_base64,
          ukey_base64,
          aad,
          olddatakey_base,
        ])
      } else if (ACTION === enroll_apis.RA_GET_API_KEY) {
        /**
         * RA_GET_API_KEY
         */
        create_app_info(DB, res)
      } else if (ACTION == enroll_apis.RA_HANDSHAKE_MSG0) {
        /**
         * RA_HANDSHAKE_MSG0
         */
        const json_str_params = JSON.stringify({ ...req.body })
        napi_result(enroll_apis.RA_HANDSHAKE_MSG0, res, [json_str_params])
      } else {
        res.send(_result(404, 'Not Fount', {}))
      }
    } catch (error) {
      res.send(_result(404, 'Not Fount', {}))
      logger.error(JSON.stringify(error))
    }
  })

  process.on('SIGINT', function () {
    console.log('ehsm kms service exit')
    ehsm_napi.NAPI_Finalize()
    clearInterval(nonce_cache_timer)
    process.exit(0)
  })

  app.listen(PORT, () => {
    console.log(
      `ehsm_ksm_service application listening at ${getIPAdress()}:${PORT}`
    )
  })
}
couchDB(server)
