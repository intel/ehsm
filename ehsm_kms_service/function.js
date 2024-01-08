const crypto = require('crypto')
const {
    v4: uuidv4
} = require('uuid')

const logger = require('./logger')
const {
    Definition,
    ehsm_keySpec_t,
    ehsm_keyorigin_t,
    ehsm_action_t,
    ehsm_keyusage_t,
    ehsm_padding_mode_t,
} = require('./constant')
const {
    KMS_ACTION
} = require('./apis')
const ehsm_napi = require('./ehsm_napi')

const _result = (code, msg, data = {}) => {
    return {
        code: code,
        message: msg,
        result: {
            ...data,
        }
    }
}
// base64 encode
const base64_encode = (str) => new Buffer.from(str)
    .toString('base64')

// base64 decode
const base64_decode = (base64_str) => new Buffer.from(base64_str, 'base64')
    .toString()

const ActionBypassList = [
    KMS_ACTION.enroll.Enroll,
    KMS_ACTION.common.GetVersion,
]

/**
 * Clear nonce cache for more than <NONCE_CACHE_TIME> minutes
 * nonce_database[appid]
 *  - type: array
 *  - sort: [new timestamp, old timestamp, ...]
 * @returns nonce_cache_timer, nonce_database
 */
const _nonce_cache_timer = () => {
    const nonce_database = {}
    const timer = setInterval(() => {
        try {
            for (const appid in nonce_database) {
                // slice_index  Index of the cache that exceeded the maximum time
                let slice_index =
                    nonce_database[appid] &&
                    nonce_database[appid].findIndex((nonce_data) => {
                        return (
                            new Date()
                                .getTime() - nonce_data.nonce_timestamp >
                            Definition.NONCE_CACHE_TIME
                        )
                    })
                // keep unexpired data
                if (slice_index > 0) {
                    nonce_database[appid] = nonce_database[appid].slice(0, slice_index)
                }
                // All data expired
                if (slice_index == 0) {
                    delete nonce_database[appid]
                }
            }
        } catch (error) {
            logger.error(error)
            res.send(_result(500, 'Server internal error, please contact the administrator.'))
        }
    }, Definition.NONCE_CACHE_TIME / 2)
    return {
        timer,
        nonce_database
    }
}

/**
 * Clear keyblobs with token time more than 24 hours.
 */
const _token_time_verify = (DB) => {
    setInterval(() => {
        try {
            const current_time = new Date()
                .getTime()
            const query = {
                selector: {
                    //Query criteria
                    token_expired_time: {
                        $lt: current_time
                    },
                },
                fields: ['_id',
                    '_rev',
                    'keyid',
                    'keyBlob',
                    'creator',
                    'creationDate',
                    'expireTime',
                    'alias',
                    'keyspec',
                    'origin',
                    'keyState',
                    'sessionkeyBlob',
                    'token_expired_time'
                ], // Fields returned after query
                limit: 10000,
            }
            DB.partitionedFind('cmk', query) // Query expired cmks
                .then((cmks_res) => {
                    if (cmks_res.docs.length > 0) {
                        for (const cmk_item of cmks_res.docs) {
                            cmk_item.keyBlob = ''
                        }
                        DB.bulk({
                            docs: cmks_res.docs
                        }) // Batch delete expired cmks
                            .catch((err) => {
                                logger.error(err)
                            })
                    }
                })
                .catch((err) => {
                    logger.error(err)
                })
        } catch (err) {
            logger.error(err)
        }
    }, Definition.TOKEN_LOOP_CLEAR_TIME)
}

/**
 * CMK is valid for 5 years and 10 days
 * Clean up CMK overdue for more than ten days at three o'clock every day .
 * First, find out all expired items exceeding s from the database .
 * Second, add and delete fields for each data .
 * Last, batch deletion using data with deletion field .
 *
 * @returns _cmk_cache_timer
 */
const _cmk_cache_timer = (DB) => {
    let nowTime = new Date()
        .getTime()
    let recent = new Date()
        .setHours(Definition.CMK_LOOP_CLEAR_EXECUTION_TIME) // Time stamp at three o'clock of the day
    if (recent < nowTime) {
        recent += 24 * 3600000
    }
    const timer = setTimeout(() => {
        setInterval(() => {
            try {
                const current_time = new Date()
                    .getTime() + Definition.CMK_EXPIRE_TIME_EXPAND
                const query = {
                    selector: {
                        //Query criteria
                        expireTime: {
                            $lt: current_time
                        },
                    },
                    fields: ['_id', '_rev'], // Fields returned after query
                    limit: 10000,
                }
                DB.partitionedFind('cmk', query) // Query expired cmks
                    .then((cmks_res) => {
                        if (cmks_res.docs.length > 0) {
                            for (const cmk_item of cmks_res.docs) {
                                cmk_item._deleted = true
                            }
                            DB.bulk({
                                docs: cmks_res.docs
                            }) // Batch delete expired cmks
                                .catch((err) => {
                                    logger.error(err)
                                })
                        }
                    })
                    .catch((err) => {
                        logger.error(err)
                    })
            } catch (err) {
                logger.error(err)
            }
        }, Definition.CMK_LOOP_CLEAR_TIME)
    }, recent - nowTime)

    return {
        timer
    }
}

/**
 * @param {object} napi_res
 * @param {object} res
 * @param {string} appid
 * @param {object} DB
 * @param {object} payload
 * Fields contained in the cmk document:
 *    _id | keyid | keyBlob | creator | creationDate | expireTime | alias | keyspec | origin | keyState
 *
 * After storing cmk successfully, return the keyid to the user
 */
function store_cmk(napi_res, res, appid, payload, DB) {
    try {
        const creationDate = new Date()
            .getTime()
        const keyid = uuidv4()
        let {
            keyspec,
            origin,
            keyusage
        } = payload
        const cmkData = {
            _id: `cmk:${keyid}`,
            keyid,
            keyBlob: napi_res.result.cmk,
            creator: appid,
            creationDate,
            expireTime: creationDate + Definition.CMK_EFFECTIVE_DURATION,
            alias: '',
            keyspec,
            origin,
            keyusage,
            keyState: 1,
        }

        if (origin === ehsm_keyorigin_t.EH_EXTERNAL_KEY) {
            cmkData.sessionkeyBlob = ''
        }

        DB.insert(cmkData)
            .then((r) => {
                delete napi_res.result.cmk // Delete cmk in NaPi result
                napi_res.result.keyid = keyid // The keyID field is added to the result returned to the user
                res.send(napi_res)
            })
            .catch((e) => {
                res.send(_result(400, 'create cmk failed', e))
            })
    } catch (e) {
        res.send(_result(400, 'create cmk failed', e))
    }
}

/**
 * ehsm napi result
 * If the value of the result is not equal to 200, the result is directly returned to the user
 * @param {function name} action
 * @param {object} res
 * @param {EHSM_FFI_CALL function params} params
 * @returns napi result | false
 */
function napi_result(action, res, payload) {
    try {
        let jsonParam = {
            action: ehsm_action_t[action],
            payload
        }
        let ret_json = ehsm_napi(JSON.stringify(jsonParam))
        if (ret_json.code != 200) {
            if (res != undefined) {
                res.send(ret_json)
            }
            return false
        } else {
            return ret_json
        }
    } catch (e) {
        logger.error(e)
        if (res != undefined) {
            res.send(_result(500, 'Server internal error, please contact the administrator.'))
        }
        return false
    }
}

/**
 * test create_user_info save in couchDB
 * @param {object} DB
 * @param {object} res
 * Fields contained in the user_info document:
 * _id | appid | apikey | cmk
 */
const create_user_info = (action, DB, res, req) => {
    const json_str_params = JSON.stringify({
        ...req.body
    })
    let napi_res = napi_result(action, res, {
        json_str_params
    })

    if (napi_res) {
        const {
            appid,
            apikey
        } = napi_res.result
        let cmk_res = napi_result(KMS_ACTION.cryptographic.CreateKey, res, {
            keyspec: ehsm_keySpec_t.EH_AES_GCM_256,
            origin: ehsm_keyorigin_t.EH_INTERNAL_KEY,
            keyusage: ehsm_keyusage_t.EH_KEYUSAGE_ENCRYPT_DECRYPT
        })
        if (cmk_res) {
            const {
                cmk
            } = cmk_res.result
            let apikey_encrypt_res = napi_result(KMS_ACTION.cryptographic.Encrypt, res, {
                cmk,
                plaintext: apikey,
                aad: '',
            })
            if (apikey_encrypt_res) {
                const {
                    ciphertext
                } = apikey_encrypt_res.result
                DB.insert({
                    _id: `user_info:${appid}`,
                    appid,
                    apikey: ciphertext,
                    cmk: cmk,
                })
                    .then((r) => {
                        if (napi_res.result.apikey) {
                            delete napi_res.result.apikey
                        }
                        res.send(_result(200, 'successful', {
                            ...napi_res.result
                        }))
                    })
                    .catch((e) => {
                        res.send(_result(400, 'create app info faild', e))
                    })
            }
        }
    }
}

/**
 * enroll： retrieve appid&apikey from ehsm-core enclave and store them into couchDB
 * @param {object} DB
 * @param {object} res
 * Fields contained in the user_info document:
 * _id | appid | apikey | cmk
 */
const enroll_user_info = (action, DB, res, req) => {
    let napi_res = napi_result(action, res, {})

    if (napi_res) {
        const {
            appid,
            apikey
        } = napi_res.result
        let cmk_res = napi_result(KMS_ACTION.cryptographic.CreateKey, undefined, {
            keyspec: ehsm_keySpec_t.EH_AES_GCM_256,
            origin: ehsm_keyorigin_t.EH_INTERNAL_KEY,
            keyusage: ehsm_keyusage_t.EH_KEYUSAGE_ENCRYPT_DECRYPT
        })
        let sm_default_cmk_res = napi_result(KMS_ACTION.cryptographic.CreateKey, undefined, {
            keyspec: ehsm_keySpec_t.EH_AES_GCM_256,
            origin: ehsm_keyorigin_t.EH_INTERNAL_KEY,
            keyusage: ehsm_keyusage_t.EH_KEYUSAGE_ENCRYPT_DECRYPT
        })
        if (cmk_res && sm_default_cmk_res) {
            const {
                cmk
            } = cmk_res.result
            // create a default secret manager CMK for current appids
            const sm_default_cmk = sm_default_cmk_res.result.cmk
            let apikey_encrypt_res = napi_result(KMS_ACTION.cryptographic.Encrypt, undefined, {
                cmk,
                plaintext: base64_encode(apikey),
                aad: ''
            })
            if (apikey_encrypt_res) {
                const {
                    ciphertext
                } = apikey_encrypt_res.result
                DB.insert({
                    _id: `user_info:${appid}`,
                    appid,
                    apikey: ciphertext,
                    cmk: cmk,
                    sm_default_cmk,
                })
                    .then((r) => {
                        res.send(_result(200, 'successful', {
                            ...napi_res.result
                        }))
                    })
                    .catch((e) => {
                        logger.error('database is unavailable')
                        res.send(_result(500, 'enroll user info failed', e))
                    })
            } else {
                logger.error('encrypt apikey failed')
                res.send(_result(500, 'enroll user info failed'))
            }
        } else {
            res.send(_result(400, 'enroll user info failed'))
        }
    }
}
/**
 * The parameters of non empty parameter values in set sign_params are sorted from small
 * to large according to the ASCII code of the parameter name (dictionary order),
 * and the format of URL key value pairs (i.e. key1 = value1 & key2 = Value2...)
 * is spliced into a string
 * @param {object} sign_params
 * @returns string
 */
const params_sort_str = (sign_params) => {
    let str = ''
    try {
        const sort_params_key_arr = Object.keys(sign_params)
            .sort()
        for (var k of sort_params_key_arr) {
            if (
                sign_params[k] != '' &&
                sign_params[k] != undefined &&
                sign_params[k] != null
            ) {
                str +=
                    (str && '&' + '') +
                    k +
                    '=' +
                    (typeof sign_params[k] == 'object' ?
                        params_sort_str(sign_params[k]) :
                        sign_params[k])
            }
        }
        return str
    } catch (error) {
        logger.error(error)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return str
    }
}

/**
 * The calibration time error is within <MAX_TIME_STAMP_DIFF> minutes
 * @param {string} timestamp
 * @returns true | false
 */
const _checkTimestamp = (timestamp) => {
    return Math.abs(new Date()
        .getTime() - timestamp) < Definition.MAX_TIME_STAMP_DIFF
}

const getIPAdress = () => {
    try {
        var interfaces = require('os')
            .networkInterfaces()
        for (var devName in interfaces) {
            var iface = interfaces[devName]
            for (var i = 0; i < iface.length; i++) {
                var alias = iface[i]
                if (
                    alias.family === 'IPv4' &&
                    alias.address !== '127.0.0.1' &&
                    !alias.internal
                ) {
                    return alias.address
                }
            }
        }
    } catch (error) {
        logger.error(error)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
    }
}

/**
 * check params
 */
const _checkParams = function (req, res, next, nonce_database, DB) {
    try {
        const ACTION = req.query.Action

        let ip = req.ip
        if (ip.substr(0, 7) == '::ffff:') {
            ip = ip.substr(7)
        }
        const _logData = {
            body: req.body,
            query: req.query,
            ip,
        }
        logger.info(JSON.stringify(_logData))
        if (ActionBypassList.includes(ACTION)) {
            next()
            return
        }
        const {
            appid,
            nonce, // nonce is a optional param.
            timestamp,
            sign,
            payload
        } = req.body
        if (!appid || !timestamp || !sign) {
            res.send(_result(400, 'Missing required parameters'))
            return
        }
        // cryptographic must be has payload
        if (ACTION === KMS_ACTION.cryptographic[ACTION] && !payload) {
            res.send(_result(400, 'Missing required parameters'))
            return
        }
        if (
            typeof appid != 'string' ||
            typeof timestamp != 'string' ||
            (payload && typeof payload != 'object') ||
            typeof sign != 'string'
        ) {
            res.send(_result(400, 'param type error'))
            return
        }
        if (nonce != null && nonce != undefined) {
            if (nonce.length > Definition.MAX_NONCE_LEN) {
                res.send(_result(400, 'Nonce length error'))
                return
            }
        }
        if (timestamp.length != Definition.TIMESTAMP_LEN) {
            res.send(_result(400, 'Timestamp length error'))
            return
        }
        if (!_checkTimestamp(timestamp)) {
            res.send(_result(400, 'Timestamp error'))
            return
        }
        /**
         * Cache nonce locally after receiving the request
         * nonce_database - object
         *  {
         *    <appid>: [nonce_data，nonce_data]
         *  }
         * nonce_data - object
         *  {
         *    nonce: ****
         *    nonce_timestamp: new Date().getTime()
         *  }
         */
        const nonce_data = {
            nonce,
            timestamp,
            nonce_timestamp: new Date()
                .getTime()
        }
        if (!nonce_database[appid]) {
            nonce_database[appid] = [nonce_data]
        } else if (
            !!nonce_database[appid] &&
            nonce_database[appid].findIndex(
                (nonce_data) => nonce_data.nonce == nonce
            ) > -1 &&
            nonce_database[appid].findIndex(
                (nonce_data) => nonce_data.timestamp == timestamp
            ) > -1
        ) {
            res.send(_result(400, "Timestamp can't be repeated in 20 minutes"))
            return
        } else {
            nonce_database[appid].unshift(nonce_data)
        }

        // check payload
        const checkPayload = require('./payload_checker')
            .checkPayload
        if (!checkPayload(req, res)) {
            return
        }

        // check sign
        let sign_params = {
            appid,
            nonce,
            timestamp,
            payload
        }

        gen_hmac(DB, appid, sign_params)
            .then(result => {
                if (result.hmac.length == 0) {
                    res.send(_result(400, result.error))
                    return
                }
                if (sign != result.hmac) {
                    res.send(_result(400, 'sign error'))
                    return
                } else {
                    next()
                }
            })
            .catch((e) => {
                res.send(_result(400, 'database error'))
            })
    } catch (error) {
        logger.error(error)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
    }
}

/**
 * Query ApiKey
 */
const _query_api_key = async (DB, appid) => {
    try {
        const db_query = {
            selector: {
                _id: `user_info:${appid}`,
            },
            fields: ['appid', 'apikey', 'cmk'],
            limit: 1,
        }
        let query_result = await DB.partitionedFind('user_info', db_query);
        if (!(query_result && query_result.docs[0])) {
            return {
                msg: 'keyid not found',
                api_key: ''
            }
        }

        let {
            cmk,
            apikey
        } = query_result.docs[0]
        let decypt_result = napi_result(
            KMS_ACTION.cryptographic.Decrypt,
            undefined, {
            cmk,
            ciphertext: apikey,
            aad: ''
        }
        )

        if (decypt_result) {
            return {
                msg: '',
                api_key: base64_decode(decypt_result.result.plaintext)
            }
        } else {
            return {
                msg: 'Decrypt key error',
                api_key: ''
            }
        }
    } catch (error) {
        logger.error(error)
    }
    return {
        msg: 'Unexcept error',
        api_key: ''
    }
}

/**
 * Gen Hmac of sign_params safely, without transfering plaintext of apikey outside enclave
 * @param {object} DB //Database object
 * @param {string} appid // APP ID from client
 * @param {object} sign_params // A list object contain string params
 * @returns {object} (error, hmac) // One object contain "error" and "hmac" attributes
 */
const gen_hmac = async (DB, appid, sign_params) => {
    try {
        const db_query = {
            selector: {
                _id: `user_info:${appid}`,
            },
            fields: ['appid', 'apikey', 'cmk'],
            limit: 1,
        }
        const query_result = await DB.partitionedFind('user_info', db_query)
        if (!query_result || !query_result.docs[0]) {
            return {
                msg: 'keyid not found',
                hmac: ''
            }
        }

        const { cmk, apikey } = query_result.docs[0];
        if (apikey && apikey.length == 0) {
            logger.error('Unexpected Error')
            return {
                error: 'Unexpected Error',
                hmac: ''
            }
        }

        const sign_string = base64_encode(params_sort_str(sign_params))
        const { result } = napi_result(
            KMS_ACTION.common.GenHmac,
            undefined,
            {
                cmk,
                apikey,
                payload: sign_string,
            })
        // check if failed
        if (!result) {
            logger.error('Unexpected Error')
            return {
                error: 'Unexpected Error',
                hmac: '',
            }
        }
        return {
            error: '',
            hmac: result.hmac,
        }

    } catch (error) {
        logger.error(error)
        return {
            error: error,
            hmac: ''
        }
    }
}

/**
 * Gen Token Hmac of importToken.
 * @param {string} sessionkey 
 * @param {object} importToken 
 * @returns {object} (error, hmac) // One object contain "error" and "hmac" attributes
 */
const gen_token_hmac = async (sessionkey, importToken) => {
    try {
        const { result } = napi_result(
            KMS_ACTION.common.GenTokenHmac,
            undefined,
            {
                sessionkey,
                importToken,
            })
        return {
            error: '',
            hmac: result.hmac,
        }

    } catch (error) {
        logger.error(error)
        return {
            error: error,
            hmac: ''
        }
    }
}

/**
 * Compare string size on const time.
 * @param {string} str1 
 * @param {string} str2 
 * @returns true | false
 */
function consttime_equal_compare(str1, str2) {
    let result = 0
    if (str1 == undefined || str2 == undefined) {
        return true;
    }
    if (str1.length !== str2.length) {
        return false;
    }
    for (let i = 0; i < str1.length; i++) {
        result |= str1[i] ^ str2[i];
    }
    return !result;
}

module.exports = {
    getIPAdress,
    base64_encode,
    base64_decode,
    _checkParams,
    _result,
    napi_result,
    create_user_info,
    enroll_user_info,
    _nonce_cache_timer,
    store_cmk,
    _cmk_cache_timer,
    gen_hmac,
    gen_token_hmac,
    _token_time_verify,
    consttime_equal_compare,
}