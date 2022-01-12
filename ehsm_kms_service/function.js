const crypto = require('crypto')

const logger = require('./logger')
const { MAX_TIME_STAMP_DIFF, TIMESTAMP_LEN } = require('./constant')
const { ehsm_kms_params } = require('./ehsm_kms_params.js')
const { cryptographic_apis, enroll_apis } = require('./apis')

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
    res.send(_result(404, 'Not Fount', {}))
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
    res.send(_result(404, 'Not Fount', {}))
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
    if (
      ACTION === enroll_apis.RA_GET_API_KEY ||
      ACTION === enroll_apis.RA_HANDSHAKE_MSG0
    ) {
      next()
      return
    }
    const { appid, timestamp: nonce, timestamp, sign, payload } = req.body
    if (!appid || !nonce || !timestamp || !sign || !payload) {
      res.send(_result(400, 'Missing required parameters'))
      return
    }
    if (
      typeof appid != 'string' ||
      typeof nonce != 'string' ||
      typeof timestamp != 'string' ||
      typeof payload != 'object' ||
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
    // check payload
    const _checkPayload_res = _checkPayload(req, res, next)
    if (!_checkPayload_res) {
      return
    }

    // check sign
    let sign_params = { appid, timestamp, payload }
    let sign_string = params_sort_str(sign_params)
    /**
     * db_query : couchdb query condition
     */
    const db_query = {
      selector: {
        _id: appid,
      },
      fields: ['appid', 'appkey'],
      limit: 1,
    }
    DB.find(db_query)
      .then((r) => {
        if (r.docs[0]) {
          let local_sign = crypto
            .createHmac('sha256', r.docs[0].appkey)
            .update(sign_string, 'utf8')
            .digest('base64')
          if (sign != local_sign) {
            res.send(_result(400, 'sign error'))
            return
          } else {
            next()
          }
        } else {
          res.send(_result(400, 'Appid not found'))
        }
      })
      .catch((e) => {
        res.send(_result(400, 'Appid not found'))
      })
  } catch (error) {
    res.send(_result(404, 'Not Fount', {}))
    logger.error(JSON.stringify(error))
  }
}

module.exports = {
  getIPAdress,
  base64_encode,
  base64_decode,
  _checkParams,
  _result,
}
