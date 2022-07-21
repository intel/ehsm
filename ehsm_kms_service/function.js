const crypto = require('crypto')
const { v4: uuidv4 } = require('uuid')

const logger = require('./logger')
const {
  MAX_TIME_STAMP_DIFF,
  TIMESTAMP_LEN,
  NONCE_CACHE_TIME,
  CMK_EFFECTIVE_DURATION,
  CMK_LOOP_CLEAR_TIME,
  CMK_EXPIRE_TIME_EXPAND,
  CMK_LOOP_CLEAR_EXECUTION_TIME,
} = require('./constant')
const { ehsm_kms_params } = require('./ehsm_kms_params.js')
const {
  enroll_apis,
  cryptographic_apis,
  key_management_apis,
  common_apis,
} = require('./apis')
const ehsm_napi = require('./ehsm_napi')

const _result = (code, msg, data = {}) => {
  return {
    code: code,
    message: msg,
    result: {
      ...data,
    },
  }
}
// base64 encode
const base64_encode = (str) => new Buffer.from(str).toString('base64')

// base64 decode
const base64_decode = (base64_str) =>
  new Buffer.from(base64_str, 'base64').toString()
const is_base64 = (base64_str) => {
  if (base64_str == undefined ||
      typeof base64_str != 'string' ||
      base64_str.length == 0 ||
      (base64_str.length % 4) != 0) {
    return false
  }
  return /^[a-zA-Z0-9\+\/]+(\={0,2})$/gi.test(base64_str)
};

const ActionBypassList = [
  enroll_apis.RA_GET_API_KEY,
  enroll_apis.RA_HANDSHAKE_MSG0,
  enroll_apis.RA_HANDSHAKE_MSG2,
  enroll_apis.Enroll,
  common_apis.GetVersion,
]

/**
 * Clear nonce cache for more than <NONCE_CACHE_TIME> minutes
 * nonce_database[appid]
 *  - type: array
 *  - sort: [new timestamp, old timestamp, ...]
 * @returns nonce_cache_timer, nonce_database
 */
const _nonce_cache_timer = () => {
  const nonce_database = {}
  const timer = setInterval(() => {
    try {
      for (const appid in nonce_database) {
        // slice_index  Index of the cache that exceeded the maximum time
        let slice_index =
          nonce_database[appid] &&
          nonce_database[appid].findIndex((nonce_data) => {
            return (
              new Date().getTime() - nonce_data.nonce_timestamp >
              NONCE_CACHE_TIME
            )
          })
        // keep unexpired data
        if (slice_index > 0) {
          nonce_database[appid] = nonce_database[appid].slice(0, slice_index)
        }
        // All data expired
        if (slice_index == 0) {
          delete nonce_database[appid]
        }
      }
    } catch (error) {
      res.send(_result(404, 'Not Found', {}))
      logger.error(JSON.stringify(error))
    }
  }, NONCE_CACHE_TIME / 2)
  return { timer, nonce_database }
}

/**
 * CMK is valid for 5 years and 10 days
 * Clean up CMK overdue for more than ten days at three o'clock every day .
 * First, find out all expired items exceeding s from the database .
 * Second, add and delete fields for each data .
 * Last, batch deletion using data with deletion field .
 *
 * @returns _cmk_cache_timer
 */
const _cmk_cache_timer = (DB) => {
  let nowTime = new Date().getTime()
  let recent = new Date().setHours(CMK_LOOP_CLEAR_EXECUTION_TIME) // Time stamp at three o'clock of the day
  if (recent < nowTime) {
    recent += 24 * 3600000
  }
  const timer = setTimeout(() => {
    setInterval(() => {
      try {
        const current_time = new Date().getTime() + CMK_EXPIRE_TIME_EXPAND
        const query = {
          selector: {
            //Query criteria
            expireTime: { $lt: current_time },
          },
          fields: ['_id', '_rev'], // Fields returned after query
          limit: 10000,
        }
        DB.partitionedFind('cmk', query) // Query expired cmks
          .then((cmks_res) => {
            if (cmks_res.docs.length > 0) {
              for (const cmk_item of cmks_res.docs) {
                cmk_item._deleted = true
              }
              DB.bulk({ docs: cmks_res.docs }) // Batch delete expired cmks
                .catch((err) => {
                  console.log(err)
                })
            }
          })
          .catch((err) => {
            console.log(err)
          })
      } catch (err) {
        console.log(err)
      }
    }, CMK_LOOP_CLEAR_TIME)
  }, recent - nowTime)

  return { timer }
}

/**
 * @param {object} napi_res
 * @param {object} res
 * @param {string} appid
 * @param {object} DB
 * @param {object} payload
 * Fields contained in the cmk document:
 *    _id | keyid | keyBlob | creator | creationDate | expireTime | alias | keyspec | origin | keyState
 *
 * After storing cmk successfully, return the keyid to the user
 */
function store_cmk(napi_res, res, appid, payload, DB) {
  try {
    const creationDate = new Date().getTime()
    const keyid = uuidv4()
    let { keyspec, origin } = payload

    DB.insert({
      _id: `cmk:${keyid}`,
      keyid,
      keyBlob: napi_res.result.cmk,
      creator: appid,
      creationDate,
      expireTime: creationDate + CMK_EFFECTIVE_DURATION,
      alias: '',
      keyspec,
      origin,
      keyState: 1,
    })
      .then((r) => {
        delete napi_res.result.cmk // Delete cmk in NaPi result
        napi_res.result.keyid = keyid // The keyID field is added to the result returned to the user
        res.send(napi_res)
      })
      .catch((e) => {
        res.send(_result(400, 'create cmk failed', e))
      })
  } catch (e) {
    res.send(_result(400, 'create cmk failed', e))
  }
}

/**
 * ehsm napi result
 * If the value of the result is not equal to 200, the result is directly returned to the user
 * @param {function name} action
 * @param {object} res
 * @param {NAPI_* function params} params
 * @returns napi result | false
 */
function napi_result(action, res, params) {
  try {
    const napi_res = ehsm_napi[`NAPI_${action}`](...params)
    if (JSON.parse(napi_res).code != 200) {
      res.send(napi_res)
      return false
    } else {
      return JSON.parse(napi_res)
    }
    // })
  } catch (e) {
    res.send(_result(400, 'Parsing error'))
    return false
  }
}

/**
 * test create_user_info save in couchDB
 * @param {object} DB
 * @param {object} res
 * Fields contained in the user_info document:
 * _id | appid | apikey | cmk
 */
const create_user_info = (action, DB, res, req) => {
  const json_str_params = JSON.stringify({ ...req.body })
  let napi_res = napi_result(action, res, [json_str_params])

  if (napi_res) {
    const { appid, apikey } = napi_res.result
    let cmk_res = napi_result(cryptographic_apis.CreateKey, res, [0, 0])
    if (cmk_res) {
      const { cmk } = cmk_res.result
      let apikey_encrypt_res = napi_result(cryptographic_apis.Encrypt, res, [
        cmk,
        apikey,
        '',
      ])
      if (apikey_encrypt_res) {
        const { ciphertext } = apikey_encrypt_res.result
        DB.insert({
          _id: `user_info:${appid}`,
          appid,
          apikey: ciphertext,
          cmk: cmk,
        })
          .then((r) => {
            if (napi_res.result.apikey) {
              delete napi_res.result.apikey
            }
            res.send(_result(200, 'successful', { ...napi_res.result }))
          })
          .catch((e) => {
            res.send(_result(400, 'create app info faild', e))
          })
      }
    }
  }
}

/**
 * enroll： retrieve appid&apikey from ehsm-core enclave and store them into couchDB
 * @param {object} DB
 * @param {object} res
 * Fields contained in the user_info document:
 * _id | appid | apikey | cmk
 */
const enroll_user_info = (action, DB, res, req) => {
  let napi_res = napi_result(action, res, [])

  if (napi_res) {
    const { appid, apikey } = napi_res.result
    let cmk_res = napi_result(cryptographic_apis.CreateKey, res, [0, 0])
    let sm_default_cmk_res = napi_result(cryptographic_apis.CreateKey, res, [0, 0])
    if (cmk_res && sm_default_cmk_res) {
      const { cmk } = cmk_res.result
      // create a default secret manager CMK for current appids
      const sm_default_cmk = sm_default_cmk_res.result.cmk
      let apikey_encrypt_res = napi_result(cryptographic_apis.Encrypt, res, [
        cmk,
        apikey,
        '',
      ])
      if (apikey_encrypt_res) {
        const { ciphertext } = apikey_encrypt_res.result
        DB.insert({
          _id: `user_info:${appid}`,
          appid,
          apikey: ciphertext,
          cmk: cmk,
          sm_default_cmk,
        })
          .then((r) => {
            res.send(_result(200, 'successful', { ...napi_res.result }))
          })
          .catch((e) => {
            res.send(_result(400, 'enroll user info faild', e))
          })
      }
    } else {
      res.send(_result(400, 'enroll user info faild'))
    }
  }
}
/**
 * The parameters of non empty parameter values in set sign_params are sorted from small
 * to large according to the ASCII code of the parameter name (dictionary order),
 * and the format of URL key value pairs (i.e. key1 = value1 & key2 = Value2...)
 * is spliced into a string
 * @param {object} sign_params
 * @returns string
 */
const params_sort_str = (sign_params) => {
  let str = ''
  try {
    const sort_params_key_arr = Object.keys(sign_params).sort()
    for (var k of sort_params_key_arr) {
      if (
        sign_params[k] != '' &&
        sign_params[k] != undefined &&
        sign_params[k] != null
      ) {
        str +=
          (str && '&' + '') +
          k +
          '=' +
          (typeof sign_params[k] == 'object'
            ? params_sort_str(sign_params[k])
            : sign_params[k])
      }
    }
    return str
  } catch (error) {
    res.send(_result(404, 'Not Found', {}))
    logger.error(JSON.stringify(error))
    return str
  }
}

/**
 * The calibration time error is within <MAX_TIME_STAMP_DIFF> minutes
 * @param {string} timestamp
 * @returns true | false
 */
const _checkTimestamp = (timestamp) => {
  return Math.abs(new Date().getTime() - timestamp) < MAX_TIME_STAMP_DIFF
}

const getIPAdress = () => {
  try {
    var interfaces = require('os').networkInterfaces()
    for (var devName in interfaces) {
      var iface = interfaces[devName]
      for (var i = 0; i < iface.length; i++) {
        var alias = iface[i]
        if (
          alias.family === 'IPv4' &&
          alias.address !== '127.0.0.1' &&
          !alias.internal
        ) {
          return alias.address
        }
      }
    }
  } catch (error) {
    logger.error(JSON.stringify(error))
    res.send(_result(404, 'Not Found', {}))
  }
}

/**
 * Verify each parameter in the payload, such as data type,
 * data length, whether it is the specified value,
 * whether it is required, etc.
 * For parameter description, see <ehsm_kms_params.js>
 * @param {object} req
 * @param {object} res
 * @returns true | false
 */
const _checkPayload = function (req, res) {
  try {
    const action = req.query.Action
    const { payload } = req.body
    const currentPayLoad = ehsm_kms_params[action]
    for (const key in currentPayLoad) {
      if (
        (payload[key] == undefined || payload[key] == '' || !payload[key]) &&
        currentPayLoad[key].required
      ) {
        res.send(_result(400, 'Missing required parameters'))
        return false
      }
      if (currentPayLoad[key].type == 'string' && payload[key]) {
        if (typeof payload[key] != 'string') {
          res.send(_result(400, `${key} must be of string type`))
          return false
        }
        if (
          payload[key] != undefined &&
          ((currentPayLoad[key].maxLength &&
            payload[key].length > currentPayLoad[key].maxLength) ||
            (currentPayLoad[key].minLength &&
              payload[key].length < currentPayLoad[key].minLength))
        ) {
          res.send(_result(400, `${key} length error`))
          return false
        }
      }
      if (currentPayLoad[key].type == 'base64' && payload[key]) {
        if (typeof payload[key] != 'string') {
          res.send(_result(400, `${key} must be of base64 string type`))
          return false
        }
        if (
          payload[key] != undefined &&
          ((currentPayLoad[key].maxLength &&
            payload[key].length > currentPayLoad[key].maxLength) ||
            (currentPayLoad[key].minLength &&
              payload[key].length < currentPayLoad[key].minLength))
        ) {
          res.send(_result(400, `${key} length error`))
          return false
        }
        if (!is_base64(payload[key])) {
          res.send(_result(400,  `${key} not a vailed base64 string`))
          return false
        }
      }
      if (currentPayLoad[key].type == 'int' && payload[key]) {
        if (!Number.isInteger(payload[key])) {
          res.send(_result(400, `${key} must be of integer type`))
          return false
        }
        if (
          payload[key] != undefined &&
          ((currentPayLoad[key].maxNum &&
            payload[key] > currentPayLoad[key].maxNum) ||
            (currentPayLoad[key].minNum &&
              payload[key] < currentPayLoad[key].minNum))
        ) {
          res.send(
            _result(
              400,
              `${key} must be between ${currentPayLoad[key].minNum} and ${currentPayLoad[key].maxNum}`
            )
          )
          return false
        }
      }
      if (currentPayLoad[key].type == 'const' && payload[key]) {
        if (!currentPayLoad[key].arr.includes(payload[key])) {
          res.send(
            _result(400, currentPayLoad[key].errortext || `${key} error`)
          )
          return false
        }
      }
    }
    return true
  } catch (error) {
    res.send(_result(400, 'Parameter exception', {}))
    logger.error(JSON.stringify(error))
    return false
  }
}

/**
 * check params
 */
const _checkParams = function (req, res, next, nonce_database, DB) {
  try {
    const ACTION = req.query.Action

    let ip = req.ip
    if (ip.substr(0, 7) == '::ffff:') {
      ip = ip.substr(7)
    }
    const _logData = {
      body: req.body,
      query: req.query,
      ip,
    }
    logger.info(JSON.stringify(_logData))
    if ( ActionBypassList.includes(ACTION) ) {
      next()
      return
    }
    const { appid, timestamp: nonce, timestamp, sign, payload } = req.body
    if (
      !appid ||
      !timestamp ||
      !sign ||
      (ACTION !== key_management_apis[ACTION] && !payload)
    ) {
      res.send(_result(400, 'Missing required parameters'))
      return
    }
    if (
      typeof appid != 'string' ||
      typeof timestamp != 'string' ||
      (payload && typeof payload != 'object') ||
      typeof sign != 'string'
    ) {
      res.send(_result(400, 'param type error'))
      return
    }
    if (timestamp.length != TIMESTAMP_LEN) {
      res.send(_result(400, 'Timestamp length error'))
      return
    }
    if (!_checkTimestamp(timestamp)) {
      res.send(_result(400, 'Timestamp error'))
      return
    }
    /**
     * Cache nonce locally after receiving the request
     * nonce_database - object
     *  {
     *    <appid>: [nonce_data，nonce_data]
     *  }
     * nonce_data - object
     *  {
     *    nonce: ****
     *    nonce_timestamp: new Date().getTime()
     *  }
     */
    const nonce_data = { nonce, nonce_timestamp: new Date().getTime() }
    if (!nonce_database[appid]) {
      nonce_database[appid] = [nonce_data]
    } else if (
      !!nonce_database[appid] &&
      nonce_database[appid].findIndex(
        (nonce_data) => nonce_data.nonce == nonce
      ) > -1
    ) {
      res.send(_result(400, "Timestamp can't be repeated in 20 minutes"))
      return
    } else {
      nonce_database[appid].unshift(nonce_data)
    }

    if (ACTION !== key_management_apis[ACTION]) {
      // check payload
      const _checkPayload_res = _checkPayload(req, res, next)
      if (!_checkPayload_res) {
        return
      }
    }

    // check sign
    let sign_params = { appid, timestamp, payload }

    gen_hmac(DB, appid, sign_params)
      .then(result => {
        if (result.hmac.length == 0) {
          res.send(_result(400, result.error))
          return
        }
        if (sign != result.hmac ) {
          res.send(_result(400, 'sign error'))
          return
        } else {
          next()
        }
      })
      .catch((e) => {
        res.send(_result(400, 'database error'))
      })
  } catch (error) {
    res.send(_result(404, 'Not Found', {}))
    logger.error(JSON.stringify(error))
  }
}

/**
 * ehsm napi result
 * If the value of the result is not equal to 200, the result is directly returned to the user
 * @param {function name} action
 * @param {NAPI_* function params} params
 * @returns napi result | false
 */
function napi_result_local (action, params) {
  try {
    const napi_res = ehsm_napi[`NAPI_${action}`](...params)
    let res = JSON.parse(napi_res)
    if (res && res.code == 200) {
      return res
    }
    return false
  } catch (e) {
    return false
  }
}

/**
 * Query ApiKey
 */
const _query_api_key = async (DB, appid) => {
  try {
    const db_query = {
      selector: {
        _id: `user_info:${appid}`,
      },
      fields: ['appid', 'apikey', 'cmk'],
      limit: 1,
    }
    let query_result = await DB.partitionedFind('user_info', db_query);
    if (!(query_result && query_result.docs[0])) {
      return {
        msg: 'keyid not found',
        api_key: ''
      }
    }
    let { cmk, apikey } = query_result.docs[0]
    let decypt_result = napi_result_local(
      cryptographic_apis.Decrypt,
      [cmk, apikey, '']
    )
    if (decypt_result) {
      return {
        msg: '',
        api_key: decypt_result.result.plaintext
      }
    } else {
      return {
        msg: 'Decrypt key error',
        api_key: ''
      }
    }
  } catch (error) {
    logger.error(JSON.stringify(error))
  }
  return {
    msg: 'Unexcept error',
    api_key: ''
  }
}

/**
 * Gen Hmac 
 * @param {object} DB //Database object
 * @param {string} appid // APP ID from client
 * @param {object} sign_params // A list object contain string params
 * @returns {object} (error, hmac) // One object contain "error" and "hmac" attributes
 */
const gen_hmac = async (DB, appid, sign_params) => {
  try {
    let { msg, api_key } = await _query_api_key(DB, appid)
    if (api_key && api_key.length == 0) {
      logger.error(msg)
      return {
        error: msg,
        hmac: ''
      }
    }
    let sign_string = params_sort_str(sign_params)
    let sign_result = crypto.createHmac('sha256', api_key)
      .update(sign_string, 'utf8')
      .digest('base64')
    return {
      error: '',
      hmac: sign_result
    }
  } catch (error) {
    logger.error(JSON.stringify(error))
    return {
      error: error,
      hmac: ''
    }
  }
}

module.exports = {
  getIPAdress,
  base64_encode,
  base64_decode,
  _checkParams,
  _result,
  napi_result,
  create_user_info,
  enroll_user_info,
  _nonce_cache_timer,
  store_cmk,
  _cmk_cache_timer,
  gen_hmac,
}
