const nano = require('nano')
const { kms_config } = require('./constant')
const logger = require('./logger')

async function connectDB(server) {
    let dburl = `http://${kms_config.database.username}:${kms_config.database.password}@${kms_config.database.server}:${kms_config.database.port}`
    const nanoDb = nano(dburl)
    let DB
    try {
        await nanoDb.db.create(kms_config.database.db, { partitioned: true })
        DB = await nanoDb.use(kms_config.database.db)
    } catch (e) {
        DB = await nanoDb.use(kms_config.database.db)
    }
    if (DB) {
        server(DB)
    } else {
        logger.error('couchdb connect error')
    }
}

module.exports = connectDB
