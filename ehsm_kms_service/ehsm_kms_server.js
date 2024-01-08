const express = require('express')
const { load_kms_config, kms_config, ehsm_action_t } = require('./constant')
const logger = require('./logger')
const https = require('https')
const fs = require('fs')
const openssl = require('openssl-nodejs')
const ehsm_napi = require('./ehsm_napi')
const {
    getIPAdress,
    _checkParams,
    _nonce_cache_timer,
    _cmk_cache_timer,
    base64_decode,
    base64_encode,
    _token_time_verify,
    _result
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
app.use(express.json({
    /**
     * The verify option, if supplied, is called as verify(req, res, buf, encoding),
     * where buf is a Buffer of the raw request body and encoding is the encoding of the request.
     */
    verify: function (req, res, buf, encoding) {
        try {
            JSON.parse(buf);
        } catch (e) {
            res.send(_result(400, 'Invalid JSON'))
            throw Error('Invalid JSON');
        }
    }
}))

// To start KMS server, need to load the kms config first.
load_kms_config()

const server = (DB) => {
    /**
     *  init ehsm-core
     */
    let ret_json = ehsm_napi(JSON.stringify({ action: ehsm_action_t.EH_INITIALIZE, payload: { "run_mode": base64_encode(kms_config.service.run_mode) } }))
    if (ret_json.code != 200) {
        logger.error(ret_json.message)
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
     * Check token expiration time every twelve hours.
     */
    _token_time_verify(DB)

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
        logger.info('ehsm kms service exit')
        ehsm_napi(JSON.stringify({ action: ehsm_action_t.EH_FINALIZE, payload: {} }))
        clearInterval(nonce_cache_timer)
        clearInterval(cmk_cache_timer)
        clearInterval(secret_delete_timer)
        process.exit(0)
    })

    process.on('uncaughtException', function (err) {
        logger.error(err)
    });

    // process open ssl
    try {
        if (kms_config.openssl.exist.key.length > 0 && kms_config.openssl.exist.crt.length > 0) {
            // load pem&crt from env
            createHttpsServer(base64_decode(kms_config.openssl.exist.key), base64_decode(kms_config.openssl.exist.crt))
        } else if (fs.existsSync('./openssl/privatekey.pem') && fs.existsSync('./openssl/certificate.crt')) {
            // load pem&crt from file
            createHttpsServer()
        } else {
            // load pem&crt from server created.
            // create certrequest.csr, privatekey.pem, certificate.crt of server
            let BufferVariable = build_openssl_conf_buffer()
            openssl(['req', '-config', { name: 'csr_tmp_custom.conf', buffer: BufferVariable, includes: function (key) { return false } },
                '-out', 'certrequest.csr', '-new', '-newkey', 'rsa:3072', '-nodes', '-keyout', 'privatekey.pem'], function (err, buffer) {
                    openssl(['x509', '-days', '365', '-req', '-in', 'certrequest.csr', '-signkey', 'privatekey.pem', '-out', 'certificate.crt'], function (err, buffer) {
                        createHttpsServer()
                    })
                })
        }
    } catch (e) {
        logger.error('Exception :: service Initialize exception!', e)
        process.exit(0)
    }

}

const createHttpsServer = (key, cert) => {
    if (key == undefined || cert == undefined) {
        key = fs.readFileSync('./openssl/privatekey.pem', 'utf8')
        cert = fs.readFileSync('./openssl/certificate.crt', 'utf8')
    }
    https.createServer({ key, cert }, app).listen(kms_config.service.port)
    logger.info(`ehsm_ksm_service application start on ${kms_config.service.run_mode} mode.`)
    logger.info(`ehsm_ksm_service application listening at ${getIPAdress()} with https port: ${kms_config.service.port}`)
}

const build_openssl_conf_buffer = () => {
    // create buffer by csr.conf
    const conf_buffer = fs.readFileSync('./openssl/csr.conf', 'utf8')
    let conf_custom_buffer = conf_buffer.replace('${countryName}', kms_config.openssl.create_conf.countryName)
        .replace('${localityName}', kms_config.openssl.create_conf.localityName)
        .replace('${organizationName}', kms_config.openssl.create_conf.organizationName)
        .replace('${organizationalUnitName}', kms_config.openssl.create_conf.organizationalUnitName)
        .replace('${commonName}', kms_config.openssl.create_conf.commonName)
        .replace('${emailAddress}', kms_config.openssl.create_conf.emailAddress)
    return Buffer.from(conf_custom_buffer)
}

connectDB(server)
