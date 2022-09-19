const express = require('express')

const https = require('https')
const fs = require('fs')
const openssl = require('openssl-nodejs')
const ehsm_napi = require('./ehsm_napi')
const {
    getIPAdress,
    _checkParams,
    _nonce_cache_timer,
    _cmk_cache_timer,
    base64_decode
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
    const NAPI_Initialize = ehsm_napi.NAPI_Initialize()
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
        ehsm_napi.NAPI_Finalize()
        clearInterval(nonce_cache_timer)
        clearInterval(cmk_cache_timer)
        clearInterval(secret_delete_timer)
        process.exit(0)
    })

    // process open ssl
    try {
        const {
            EHSM_CONFIG_OPENSSL_KEY, // The datas of privatekey's content which in base64 encoding.
            EHSM_CONFIG_OPENSSL_CRT // The datas of certificate's content which in base64 encoding.
        } = process.env
        if (EHSM_CONFIG_OPENSSL_KEY != undefined && EHSM_CONFIG_OPENSSL_CRT.length > 0 && EHSM_CONFIG_OPENSSL_CRT != undefined && EHSM_CONFIG_OPENSSL_CRT.length > 0) {
            // load pem&crt from env
            createHttpsServer(base64_decode(EHSM_CONFIG_OPENSSL_KEY), base64_decode(EHSM_CONFIG_OPENSSL_CRT))
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
        console.log('Exception :: service Initialize exception!', e)
        process.exit(0)
    }

}

const createHttpsServer = (key, cert) => {
    if (key == undefined || cert == undefined) {
        key = fs.readFileSync('./openssl/privatekey.pem', 'utf8')
        cert = fs.readFileSync('./openssl/certificate.crt', 'utf8')
    }
    https.createServer({ key, cert }, app).listen(HTTPS_PORT)
    console.log(`ehsm_ksm_service application listening at ${getIPAdress()} with https port: ${HTTPS_PORT}`)
}

const build_openssl_conf_buffer = () => {
    // default setting
    let conf = {
        countryName: "CN",
        localityName: "SH",
        organizationName: "Intel",
        organizationalUnitName: "Dev",
        commonName: "ehsm",
        emailAddress: "ehsm@intel.com"
    }
    // load custom setting 
    const {
        EHSM_CONFIG_OPENSSL_COUNTRYNAME,
        EHSM_CONFIG_OPENSSL_LOCALITYNAME,
        EHSM_CONFIG_OPENSSL_ORGANIZATIONNAME,
        EHSM_CONFIG_OPENSSL_ORGANIZATIONALUNITNAME,
        EHSM_CONFIG_OPENSSL_COMMONNAME,
        EHSM_CONFIG_OPENSSL_EMAILADDRESS
    } = process.env
    if (EHSM_CONFIG_OPENSSL_COUNTRYNAME) {
        conf.countryName = EHSM_CONFIG_OPENSSL_COUNTRYNAME
    }
    if (EHSM_CONFIG_OPENSSL_LOCALITYNAME) {
        conf.localityName = EHSM_CONFIG_OPENSSL_LOCALITYNAME
    }
    if (EHSM_CONFIG_OPENSSL_ORGANIZATIONNAME) {
        conf.organizationName = EHSM_CONFIG_OPENSSL_ORGANIZATIONNAME
    }
    if (EHSM_CONFIG_OPENSSL_ORGANIZATIONALUNITNAME) {
        conf.organizationalUnitName = EHSM_CONFIG_OPENSSL_ORGANIZATIONALUNITNAME
    }
    if (EHSM_CONFIG_OPENSSL_COMMONNAME) {
        conf.commonName = EHSM_CONFIG_OPENSSL_COMMONNAME
    }
    if (EHSM_CONFIG_OPENSSL_EMAILADDRESS) {
        conf.emailAddress = EHSM_CONFIG_OPENSSL_EMAILADDRESS
    }
    
    // create buffer by csr.conf
    const conf_buffer = fs.readFileSync('./openssl/csr.conf', 'utf8')
    let conf_custom_buffer = conf_buffer.replace('${countryName}', conf.countryName).replace('${localityName}', conf.localityName)
        .replace('${organizationName}', conf.organizationName).replace('${organizationalUnitName}', conf.organizationalUnitName)
        .replace('${commonName}', conf.commonName).replace('${emailAddress}', conf.emailAddress)

    return Buffer.from(conf_custom_buffer)
}

connectDB(server)
