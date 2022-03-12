const logger = require('./logger')
const {
  NONCE_CACHE_TIME,
} = require('./constant')

const _result = (code, msg, data = {}) => {
  return {
    code: code,
    message: msg,
    result: {
      ...data,
    },
  }
}
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
      logger.error(JSON.stringify(error))
    }
  }, NONCE_CACHE_TIME / 2)
  return { timer, nonce_database }
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

module.exports = {
  getIPAdress,
  _result,
  _nonce_cache_timer,
}
