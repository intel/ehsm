const express = require('express')
const {
  getIPAdress,
  _result,
  _nonce_cache_timer,
} = require('./common_function')
const {AccessPathName} = require('./access_control_api')
const {AccessRouter} = require('./access_control_server')

const app = express()
app.use(express.json())

const PORT = process.argv.slice(2)[0] || 9001
/**
   * Clear nonce cache for more than 15 minutes
   */
 const { timer: nonce_cache_timer, nonce_database } = _nonce_cache_timer()

 /**
  * AccessRouter
  */
 app.get(AccessPathName, (req, res) => {res.send(_result(200, 'Ready!', {}))})
 app.post(AccessPathName, (req, res) => AccessRouter({ req, res, nonce_database}))

 /**
  * finalize when service exit
  */
 process.on('SIGINT', function () {
   console.log('ehsm access service exit')
   clearInterval(nonce_cache_timer)
   process.exit(0)
 })

 app.listen(PORT, () => {
   console.log(
     `ehsm_access_service application listening at ${getIPAdress()}:${PORT}`
   )
 })