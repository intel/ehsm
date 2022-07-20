const crypto = require('crypto')
const logger = require('./logger')
const {
    CMK_EFFECTIVE_DURATION,
    KEYID_SECRET_MANAGER_DEFAULT_CMK
} = require('./constant')
const {
    napi_result,
    _result,
} = require('./function')
const {
    cryptographic_apis,
} = require('./apis')
const ehsm_napi = require('./ehsm_napi')

//initialize Default CMK
const Init_SM_DefaultCMK = (DB) => {
    try {
        const keyid = KEYID_SECRET_MANAGER_DEFAULT_CMK
        const query = {
            selector: {
                keyid,
            },
            fields: ['keyid',],
            limit: 1,
        }
        DB.partitionedFind('cmk', query)
            .then((cmks_res) => {
                if (cmks_res.docs.length == 0) {
                    const keyspec = 0
                    const origin = 0
                    const napi_res = JSON.parse(ehsm_napi[`NAPI_${cryptographic_apis.CreateKey}`](keyspec, origin))
                    const creationDate = new Date().getTime()
                    DB.insert({
                        _id: `cmk:${keyid}`,
                        keyid,
                        keyBlob: napi_res.result.cmk,
                        creator: 'Secret Manager',
                        creationDate,
                        expireTime: creationDate + CMK_EFFECTIVE_DURATION * 999,
                        alias: 'Secret Manager Default CMK',
                        keyspec,
                        origin,
                        keyState: 1,
                    })
                        .then((r) => {
                            console.info(`init_DefaultCMK :: create cmk seccuss.`)
                        })
                        .catch((e) => {
                            console.error(`init_DefaultCMK :: create cmk failed ${e}.`)
                        })
                } else {
                    console.info('init_DefaultCMK :: default CMK exist.')
                }
            })
    } catch (error) { }
}

/**
 *
 */
module.exports = {
    Init_SM_DefaultCMK,
}