const express = require('express')

const https = require('https')
const fs = require('fs');

const cert = {
  key: fs.readFileSync('./ssl_key/privatekey.pem', 'utf8'),
  cert: fs.readFileSync('./ssl_key/certificate.crt', 'utf8')
};

const ehsm_napi = require('./ehsm_napi')
const {
  getIPAdress,
  _checkParams,
  _nonce_cache_timer,
  _cmk_cache_timer,
} = require('./function')
const {
  init_DefaultCMK,
} = require('./secret_management')
const connectDB = require('./couchdb')
const {
  router,
  GetRouter
} = require('./router')

const app = express()
app.use(express.json())

const HTTPS_PORT = process.argv.slice(2)[0] || 9000

const server = (DB) => {
  /**
   * NAPI init
   */
  const NAPI_Initialize = ehsm_napi.NAPI_Initialize()
  if (JSON.parse(NAPI_Initialize)['code'] != 200) {
    console.log('service Initialize exception!')
    process.exit(0)
  }

  /**
   * initialize Default CMK
   */
   init_DefaultCMK(DB)
  
  /**
   * Clear nonce cache for more than 15 minutes
   */
  const { timer: nonce_cache_timer, nonce_database } = _nonce_cache_timer()

  /**
   * Clear expired cmks
   */
  const { timer: cmk_cache_timer } = _cmk_cache_timer(DB)

  /**
   * check params
   */
  app.use((req, res, next) => _checkParams(req, res, next, nonce_database, DB))

  /**
   * router
   */
  app.get('/ehsm', (req, res) => GetRouter({ req, res, DB }))
  app.post('/ehsm', (req, res) => router({ req, res, DB }))

  /**
   * NAPI finalize when service exit
   */
  process.on('SIGINT', function () {
    console.log('ehsm kms service exit')
    ehsm_napi.NAPI_Finalize()
    clearInterval(nonce_cache_timer)
    clearInterval(cmk_cache_timer)
    process.exit(0)
  })

  console.log(`ehsm_ksm_service application listening at ${getIPAdress()} with https port: ${HTTPS_PORT}`)
  https.createServer(cert, app).listen(HTTPS_PORT);

}

connectDB(server)

