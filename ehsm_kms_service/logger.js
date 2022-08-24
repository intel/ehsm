const log4js = require('log4js')

log4js.configure({
  replaceConsole: true,
  appenders: {
    cheese: {
      type: 'dateFile',
      filename: `./logs/${new Date().getDate()}/info.log`,
      encoding: 'utf-8',
      layout: {
        type: 'pattern',
        pattern:
          '{"date":"%d","level":"%p","category":"%c","host":"%h","pid":"%z","data":\'%m\'}',
      },
      pattern: '-yyyy-MM-dd',
      keepFileExt: true,
      alwaysIncludePattern: true,
    },
  },
  categories: {
    default: { appenders: ['cheese'], level: 'debug' },
  },
})

const logger = log4js.getLogger('cheese')

module.exports = logger
