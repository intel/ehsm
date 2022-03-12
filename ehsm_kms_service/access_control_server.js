const logger = require("./logger")
const { _result } = require("./common_function")

const {
  EHSM_CONFIG_DENY_SIZE_LIMIT,
  EHSM_CONFIG_DENY_TIMEOUT,
  EHSM_CONFIG_DENY_COUNT_LIMIT,
  EHSM_CONFIG_REPORTERS
} = process.env

const defense_apis = {
  CheckAccess: 'CheckAccess',
  ReportTarget: 'ReportTarget',
  CheckNonce: 'CheckNonce'
}

const default_config_value = {
  size_limit: 3000,
  time_out: 1800000, //ms defult 30 min
  count_limit: 5
}

const _DenyList = new Map()
const _Reporters = () => {
  if (EHSM_CONFIG_REPORTERS && EHSM_CONFIG_REPORTERS.length > 0) {
    return EHSM_CONFIG_REPORTERS.split('|')
  }
  return []
}
function DenyListClearUp() {
  timestamp = new Date().getTime()
  let _size_limit = parseInt(EHSM_CONFIG_DENY_SIZE_LIMIT)
  if (isNaN(_size_limit)) {
    _size_limit = default_config_value.size_limit
  }
  let _time_out = parseInt(EHSM_CONFIG_DENY_TIMEOUT)
  if (isNaN(_time_out)) {
    _time_out = default_config_value.time_out
  }

  let keys = Array.from(_DenyList.keys())
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i]
    if (_DenyList.has(key)) {
      var report_info = _DenyList.get(key)
      if (report_info.timestamp > 0 &&
        timestamp > 0 &&
        (report_info.timestamp + _time_out) < timestamp) {
          _DenyList.delete(key)
          keys.splice(i, 1)
          i--
        }
    }
  }

  if (keys.length >= _size_limit) {
    for (var i = 0; i < (keys.length - _size_limit); i++) {
      if(_DenyList.has(keys[i])) {
        _DenyList.delete(keys[i])
      }
    }
  }
}

const DefenseCheckAccess = (ip) => {
  DenyListClearUp()
  let count_limit = parseInt(EHSM_CONFIG_DENY_COUNT_LIMIT)
  if (isNaN(count_limit)) {
    count_limit = default_config_value.count_limit
  }
  return (!_DenyList.has(ip) || (_DenyList.get(ip).count < count_limit))
}

const DefenseReportTarget = (ip, timestamp) => {
  DenyListClearUp()
  let count = 0
  if (_DenyList.has(ip)) {
    var info = _DenyList.get(ip)
    count = info.count

    if (count < 0) {
      count = 0
    }

    if (info.timestamp < timestamp) {
      _DenyList.delete(ip)
    }
  }

  count = count + 1
  if(!_DenyList.has(ip)) {
    _DenyList.set(ip,
      {
        timestamp:timestamp,
        count:count
      })
  }
}
const DefenseCheckNonce = (nonce_database, appid, nonce, nonce_timestamp) => {
  const nonce_data = {
    nonce: nonce,
    nonce_timestamp: nonce_timestamp
  }

  if (!nonce_database[appid]) {
    nonce_database[appid] = [nonce_data]
    return true;
  }

  if (nonce_database[appid].findIndex(
      (nonce_data) => nonce_data.nonce == nonce
    ) > -1
  ) {
    return false
  } else {
    nonce_database[appid].unshift(nonce_data)
  }
  return true
}

const _VailedReporter = (ip_from) => {
  let _reporters = _Reporters()
  if (_reporters.length > 0) {
    if (!_reporters.includes(ip_from)) {
      return false
    }
  } else {
    logger.warn('No Reporter list configed, allow all reporter access')
  }
  return true
}

const AccessRouter = async (p) => {
  const { req, res, nonce_database} = p
  const { ip, timestamp, appid, nonce } = req.body
  const action = req.query.Action

  let ip_from = req.ip
  if (ip_from.substr(0, 7) == '::ffff:') {
    ip_from = ip_from.substr(7)
  }

  switch (action) {
    case defense_apis.CheckAccess:
      try {
        let _access = DefenseCheckAccess(ip)
        res.send(_result(200, 'successful', { access: _access}))
      } catch (error) {
        logger.error(error)
      }
      break
    case defense_apis.ReportTarget:
      try {
        if (!_VailedReporter(ip_from)) {
          res.send(_result(400, 'Illegal Access'))
          break
        }

        DefenseReportTarget(ip, timestamp)
        res.send(_result(200, 'successful'))
      } catch (error) {
        logger.error(error)
      }
      break
    case defense_apis.CheckNonce:
      try {
        let _access = DefenseCheckNonce(nonce_database, appid, nonce, timestamp)
        res.send(_result(200, 'successful', { access: _access }))
      } catch (error) {
        logger.error(error)
      }
      break
    default:
      res.send(_result(404, 'Not Found', {}))
      break
  }
}

module.exports = {
  AccessRouter,
  defense_apis,
  DefenseCheckAccess,
  DefenseReportTarget,
  DefenseCheckNonce
}