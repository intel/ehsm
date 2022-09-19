const express = require('express')
const { ehsm_action_t } = require('./constant')
const https = require('https')
const fs = require('fs')
const openssl = require('openssl-nodejs')
const ehsm_napi = require('./ehsm_napi')
const {
    getIPAdress,
    _checkParams,
    _nonce_cache_timer,
    _cmk_cache_timer,
} = require('./function')
const connectDB = require('./couchdb')
const {
    router,
    GetRouter
} = require('./router')
const {
    _secret_delete_timer
} = require('./delete_secret_thread')

const app = express()
app.use(express.json())

const HTTPS_PORT = process.argv.slice(2)[0] || 9000

const server = (DB) => {
    /**
     * NAPI init
     */
    const NAPI_Initialize = ehsm_napi.EHSM_FFI_CALL(JSON.stringify({ action: ehsm_action_t.EH_INITIALIZE, payload: {} }))
    if (JSON.parse(NAPI_Initialize)['code'] != 200) {
        console.log('service Initialize exception!')
        process.exit(0)
    }


    /**
     * start secret delete timer
     */
    const { timer: secret_delete_timer } = _secret_delete_timer(DB)

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
        ehsm_napi.EHSM_FFI_CALL(JSON.stringify({ action: ehsm_action_t.EH_FINALIZE, payload: {} }))
        clearInterval(nonce_cache_timer)
        clearInterval(cmk_cache_timer)
        clearInterval(secret_delete_timer)
        process.exit(0)
    })

    // process open ssl
    try {
        if (fs.existsSync('./openssl/privatekey.pem') && fs.existsSync('./openssl/certificate.crt')) {
            createHttpsServer();
        } else {
            // create certrequest.csr, privatekey.pem, certificate.crt of server
            openssl(['req', '-config', './openssl/csr.conf', '-out', 'certrequest.csr', '-new', '-newkey', 'rsa:3072', '-nodes', '-keyout', 'privatekey.pem'], function (err, buffer) {
                openssl(['x509', '-days', '365', '-req', '-in', 'certrequest.csr', '-signkey', 'privatekey.pem', '-out', 'certificate.crt'], function (err, buffer) {
                    createHttpsServer();
                })
            })
        }
    } catch (e) {
        console.log('Exception :: service Initialize exception!')
        process.exit(0)
    }
}

const createHttpsServer = () => {
    const ehsm_openssl_key = fs.readFileSync('./openssl/privatekey.pem', 'utf8')
    const ehsm_openssl_cert = fs.readFileSync('./openssl/certificate.crt', 'utf8')
    https.createServer({ key: ehsm_openssl_key, cert: ehsm_openssl_cert }, app).listen(HTTPS_PORT)
    console.log(`ehsm_ksm_service application listening at ${getIPAdress()} with https port: ${HTTPS_PORT}`)
}

connectDB(server)

