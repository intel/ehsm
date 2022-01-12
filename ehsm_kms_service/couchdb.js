const nano = require('nano')
const logger = require('./logger')

const {
  EHSM_CONFIG_COUCHDB_USERNAME,
  EHSM_CONFIG_COUCHDB_PASSWORD,
  EHSM_CONFIG_COUCHDB_SERVER,
  EHSM_CONFIG_COUCHDB_PORT,
  EHSM_CONFIG_COUCHDB_DB,
} = process.env

let dburl = `http://${EHSM_CONFIG_COUCHDB_USERNAME}:${EHSM_CONFIG_COUCHDB_PASSWORD}@${EHSM_CONFIG_COUCHDB_SERVER}:${EHSM_CONFIG_COUCHDB_PORT}`

const nanoDb = nano(dburl)

async function couchDB(server) {
  try {
    await nanoDb.db.create(EHSM_CONFIG_COUCHDB_DB)
  } catch (error) {
    console.log('Database connection exception', error)
  }
  const DB = await nanoDb.use(EHSM_CONFIG_COUCHDB_DB)
  server(DB)
}

module.exports = couchDB
