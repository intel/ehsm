const axios = require("axios")
const logger = require("./logger")
const { _result } = require("./common_function")
const {
  defense_apis,
  DefenseCheckAccess,
  DefenseReportTarget,
  DefenseCheckNonce
} = require("./access_control_server")

const {
  EHSM_CONFIG_DEFENSE_ENABLE,
  EHSM_CONFIG_DEFENSE_SERVER_URL,
} = process.env

const _DefenseType = {
  NONE: 1,
  LOCAL: 2,
  REMOTE: 3
}

const isVaildString = (one_string) => {
  return (one_string && typeof one_string == 'string' && one_string.length > 0)
}

const AccessPathName = '/access'

const _GetDefenseType = () => {
  if (isVaildString(EHSM_CONFIG_DEFENSE_ENABLE) &&
    EHSM_CONFIG_DEFENSE_ENABLE.toLocaleLowerCase() == 'true') {
    if (isVaildString(EHSM_CONFIG_DEFENSE_SERVER_URL)) {
      return _DefenseType.REMOTE
    } else {
      return _DefenseType.LOCAL
    }
  }
  return _DefenseType.NONE
}

const _getRemoteAPI = (action) => {
  if (isVaildString(EHSM_CONFIG_DEFENSE_SERVER_URL)) {
    var path = AccessPathName
    if (EHSM_CONFIG_DEFENSE_SERVER_URL.endsWith('/')) {
      path = path.substring(1)
    }
    return EHSM_CONFIG_DEFENSE_SERVER_URL + path + '?Action=' + action
  }
  return ''
}

const RemoteAccessApi = {
  access: () => {
    var _defenseCheckUrl = _getRemoteAPI(defense_apis.CheckAccess)
    if (_defenseCheckUrl) {
      return function (req, res, next) {
        if (req.url && req.url.startsWith(AccessPathName)) {
          next()
          return
        }
        try {
          var _opt = {
            ip: req.ip,
            timestamp: new Date().getTime(),
          }
          axios.post(_defenseCheckUrl, _opt, {timeout:1000}).then((resp) => {
            if (resp &&
              resp.status == 200 &&
              'data' in resp &&
              'result' in resp.data &&
              'access' in resp.data.result) {
                if (resp.data.result.access) {
                  next()
                  return
                } else {
                  res.send(_result(401, 'Access deny'))
                }
              } else {
                next()
              }
          }).catch((error) => {
            logger.error(JSON.stringify(error))
            next()
          })
        } catch (error) {
          logger.error(JSON.stringify(error))
          next()
        }
      }
    }
    logger.error('No defense check url config')
  },
  report: (ip, timestamp) => {
    var _defenseReportUrl = _getRemoteAPI(defense_apis.ReportTarget)
    if (!isVaildString(_defenseReportUrl)) {
      logger.error('ReportControlTarget : invaild report url config')
      return
    }

    if (!isVaildString(ip)) {
      logger.error('ReportControlTarget : invaild input ip')
      return
    }

    if (timestamp == undefined || timestamp == 0) {
      logger.error('ReportControlTarget : invaild input timestamp')
      return
    }
    try {
      var _opt = {
        ip: ip,
        timestamp: timestamp
      }
      axios.post(_defenseReportUrl, _opt, {timeout:1000}).then((resp) => {
        logger.error("report", JSON.stringify(resp.data))
      }).catch((error) => {
        logger.error(JSON.stringify(error))
      })
    } catch (error) {
      logger.error(JSON.stringify(error))
    }
  },
  checkNonce: async (nonce_database, appid, nonce, nonce_timestamp) => {
    try {
      var _checkNonceUrl = _getRemoteAPI(defense_apis.CheckNonce)
      if (!isVaildString(_checkNonceUrl)) {
        logger.error('checkNonce : invaild report url config')
        return false
      }

      if (!isVaildString(appid)) {
        logger.error('checkNonce : invaild input appid')
        return false
      }

      if (!isVaildString(nonce)) {
        logger.error('checkNonce : invaild input nonce')
        return false
      }

      if (nonce_timestamp == undefined || nonce_timestamp == 0) {
        logger.error('checkNonce : invaild input nonce_timestamp')
        return false
      }
      var _opt = {
        timestamp: nonce_timestamp,
        appid: appid,
        nonce: nonce
      }

      resp = await axios.post(_checkNonceUrl, _opt, {timeout:500})
      if (resp &&
        resp.status == 200 &&
        'data' in resp &&
        'result' in resp.data &&
        'access' in resp.data.result) {
          if (resp.data.result.access) {
            return true
          }
      }
    } catch (error) {
      logger.error(JSON.stringify(error))
    }
    return false
  }
}

const LocalAccessApi = {
  access: () => {
    return function (req, res, next) {
      try {
        if(DefenseCheckAccess(req.ip)) {
          next();
        } else {
          res.send(_result(401, 'Access deny'))
        }
      } catch (error) {
        logger.error(JSON.stringify(error))
        next()
      }
    }
  },
  report: DefenseReportTarget,
  checkNonce: async (nonce_database, appid, nonce, nonce_timestamp) => {
    return DefenseCheckNonce(nonce_database, appid, nonce, nonce_timestamp)
  }
}

const _getAccessAPI = () => {
  var type = _GetDefenseType()
  if (type == _DefenseType.REMOTE) {
    return RemoteAccessApi
  }
  if (type == _DefenseType.LOCAL) {
    return LocalAccessApi
  }
}

/**
 * Return a function when setting access control feature enable
 * undefine when disabled access control feature
*/
function AccessControl() {
  var api = _getAccessAPI()
  if (api) {
    return api.access()
  }
}

/**
  * Report access target when enabling access control feature
  * Do nothing when disabled access control feature
*/
function ReportControlTarget(iIp, iTimestamp) {
  var api = _getAccessAPI()
  if (api) {
    api.report(iIp, iTimestamp)
  }
}

/**
 * Return check nonce promise when enabling access control feature
 * undefine when disabled access control feature
*/
function CheckNonce(nonce_database, appid, nonce, nonce_timestamp) {
  var api = _getAccessAPI()
  if (api) {
    return api.checkNonce(nonce_database, appid, nonce, nonce_timestamp)
  }
}

module.exports = {
  AccessControl,
  ReportControlTarget,
  AccessPathName,
  CheckNonce
}