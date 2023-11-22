const log4js = require('log4js')

// %h: host, %z: pid, %d: date, %p: level, %f: file, %l: line, %m: log data
var log_pattern = '%h %z %d %p [%f{1}: line %l] - %m'

log4js.configure({
  replaceConsole: true,
  appenders: {
    stdout: {
      type: 'console',
      encoding: 'utf-8',
      layout: {
        type: 'pattern',
        pattern: log_pattern
      }
    },
    cheese: {
      type: 'dateFile',
      filename: `/var/log/ehsm/kms-service`,
      encoding: 'utf-8',
      layout: {
        type: 'pattern',
        pattern: log_pattern
      },
      pattern: 'yyyy-MM-dd.log',
      keepFileExt: true,
      alwaysIncludePattern: true
    },
  },
  categories: {
    default: { appenders: ['stdout', 'cheese'], level: 'info', enableCallStack: true },
  },
})

const logger = log4js.getLogger('cheese')

module.exports = logger
