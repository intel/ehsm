const nano = require('nano')

const {
  EHSM_CONFIG_COUCHDB_USERNAME,
  EHSM_CONFIG_COUCHDB_PASSWORD,
  EHSM_CONFIG_COUCHDB_SERVER,
  EHSM_CONFIG_COUCHDB_PORT,
  EHSM_CONFIG_COUCHDB_DB,
} = process.env

async function connectDB(server) {
  if (
    !EHSM_CONFIG_COUCHDB_USERNAME ||
    !EHSM_CONFIG_COUCHDB_PASSWORD ||
    !EHSM_CONFIG_COUCHDB_SERVER ||
    !EHSM_CONFIG_COUCHDB_PORT ||
    !EHSM_CONFIG_COUCHDB_DB
  ) {
    console.log('couchdb url error')
  } else {
    let dburl = `http://${EHSM_CONFIG_COUCHDB_USERNAME}:${EHSM_CONFIG_COUCHDB_PASSWORD}@${EHSM_CONFIG_COUCHDB_SERVER}:${EHSM_CONFIG_COUCHDB_PORT}`
    const nanoDb = nano(dburl)
    let DB
    try {
      await nanoDb.db.create(EHSM_CONFIG_COUCHDB_DB, { partitioned: true })
      DB = await nanoDb.use(EHSM_CONFIG_COUCHDB_DB)
    } catch (e) {
      DB = await nanoDb.use(EHSM_CONFIG_COUCHDB_DB)
    }
    if (DB) {
      server(DB)
    } else {
      console.log('couchdb connect error')
    }
  }
}

module.exports = connectDB
