const logger = require('./logger')
const { v4: uuidv4 } = require('uuid')
const {
    QUOTE_LENGTH_MAX,
    NONCE_LENGTH_MAX,
    CHALLENGE_LENGTH_MAX,
    UUID_LENGTH,
    MR_ENCLAVE_LENGTH,
    MR_SIGNER_LENGTH
} = require('./constant')
const {
    napi_result,
    _result,
    base64_encode,
    base64_decode,
    gen_hmac
} = require('./function')
const {
    cryptographic_apis
} = require('./apis')


/**
 * Verify that the parameter is string and whether it is required and the maximum length
 * @param {object} param : Variables requiring validation
 * @param {boolean} required : Whether the parameter is required
 * @param {int} maxLength [defalut=undefined] : Maximum length of string, If maxLength is undefined, the length is not verified.
 * @returns {boolean}
 */
function checkStringParam(param, required, maxLength) {
    if (param == '' || param == undefined) {
        if (required) {
            return false
        } else {
            return true
        }
    } else {
        if (typeof (param) == 'string') {
            if (maxLength != undefined && param.length > maxLength) {
                return false
            } else {
                return true
            }
        } else {
            return false
        }
    }
}

/**
 * check uuid format
 * @param {String} uuid : a uuid string, eg. 0197ad2d-c4be-4948-996d-513c6f1e****
 * @returns {boolean}
 */
function check_UUID_format(uuid) {
    if (uuid != '' && uuid != undefined) {
        if (!((/^([a-z\d]{8}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{12})$/).test(uuid))) {
            return false
        }
    }
    return true
}

/**
 * Generate a quote of the eHSM-KMS core enclave
 * @param {Object} res : response
 * @param {Object} payload
 *          ==> {r}challenge(String [1~1024]) : a string. eg. 'Y2hhbGxlbmdl'
 * @returns {Object}
 *          ==> {r}challenge(String) : a string. eg. 'Y2hhbGxlbmdl'
 *          ==> {r}quote(String) : A quote for the eHSM-KMS core enclave format in BASE64 string. eg. 'AwACAAAAAAAHAAwAk5pB∗∗∗'
 */
const generateQuote = async (res, payload, action) => {
    try {
        const { challenge } = payload
        if (checkStringParam(challenge, true, CHALLENGE_LENGTH_MAX)) {
            napi_res = napi_result(action, res, [challenge])
            napi_res && res.send(napi_res)
        } else {
            res.send(_result(400, `challenge cannot be empty, must be string and length not more than ${CHALLENGE_LENGTH_MAX}`))
            return
        }
    } catch (e) {
        console.info('generateQuote :: ', e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * Users are expected already got a valid DCAP format QUOTE. And it could use this API to send it to eHSM-KMS to do a quote verification.
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}quote(String [1~10924]) : A valid DCAP quote in BASE64 string. eg. 'AwACAAAAAAAHAAwAk5pB∗∗∗'
 *          ==> {r}nonce(String [1~1024]) : A nonce in BASE64 string. eg. 'bm9uY2U='
 *          ==> {r}policyId(String [36]) : quote policy ID. eg. '326f2049-56ab-474f-a1c0-516de230****'
 * @returns {Object}
 *          ==> {r}result(bool) : The result of quote verification. eg. 'true'
 *          ==> {r}nonce(bool) : The nonce in BASE64 string. eg. 'bm9uY2U=
 *          ==> {r}sign(String) : The HAMC sign of result and nonce calculated by the API Key. eg. 'T4DRCEZAPLBbb+d3ObD∗∗∗'
 */
const verifyQuote = async (res, appid, payload, DB, action) => {
    try {
        const { quote, nonce, policyId } = payload
        if (!checkStringParam(quote, true, QUOTE_LENGTH_MAX)) {
            res.send(_result(400, `quote cannot be empty, must be string and length not more than ${QUOTE_LENGTH_MAX}.`))
            return
        }
        if (!checkStringParam(nonce, true, NONCE_LENGTH_MAX)) {
            res.send(_result(400, `nonce cannot be empty, must be string and length not more than ${NONCE_LENGTH_MAX}.`))
            return
        }
        if (!checkStringParam(policyId, true, UUID_LENGTH)) {
            res.send(_result(400, `policyId cannot be empty, must be string and length equal ${UUID_LENGTH}.`))
            return
        }
        if (!check_UUID_format(policyId)) {
            res.send(_result(400, 'policyId format wrong.'))
            return
        }

        // query quote policy by policyId
        const query_quote_policy = {
            selector: {
                appid,
                policyId
            },
            fields: ['mr_enclave', 'mr_signer'],
            limit: 1
        }
        let quote_policy_res = await DB.partitionedFind('quote_policy', query_quote_policy)
        if (quote_policy_res.docs.length != 1) {
            res.send(_result(400, 'Invalid  policyId.'))
            return
        }
        mr_enclave = quote_policy_res.docs[0].mr_enclave
        mr_signer = quote_policy_res.docs[0].mr_signer
        napi_res = napi_result(action, res, [quote, mr_signer, mr_enclave, nonce])
        if (napi_res) {
            let { error, hmac } = await gen_hmac(DB, appid, napi_res.result)
            if (hmac.length > 0) {
                napi_res.result.sign = hmac
                res.send(napi_res)
                return
            } else {
                res.send(_result(400, 'Internal error', {}))
                return
            }
        }
    } catch (e) {
        console.info('verifyQuote :: ', e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * The UploadQuotePolicy Support uploading MRenclave and MRsigner and returning new policyid.
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}mr_enclave(String [1~1024]) : stores the hash value of the enclave measurement. eg. '870c42c59bc74c7ad22869411709e4f78ac3c76add6693bb43296b03362e5038'
 *          ==> {r}mr_signer(String [1~1024]) : stores the hash value of the enclave author’s public key. eg. 'c30446b4be9baf0f69728423ea613ef81a63e72acf7439fa0549001fd5482835'
 * @returns {Object}
 *          ==> {r}policyId(String) : a new policy ID. eg. '15ca0dd5-2d34-4221-a708-3171ffe6****'
 */
const uploadQuotePolicy = async (res, appid, payload, DB) => {
    try {
        const { mr_enclave, mr_signer } = payload
        if (!checkStringParam(mr_enclave, true)) {
            res.send(_result(400, `mr_enclave cannot be empty, must be string.`))
            return
        }
        if (!checkStringParam(mr_signer, true)) {
            res.send(_result(400, `mr_signer cannot be empty, must be string.`))
            return
        }
        if(mr_enclave.length != MR_ENCLAVE_LENGTH){
            res.send(_result(400, `mr_enclave length must be ${MR_ENCLAVE_LENGTH}.`))
            return
        }
        if(mr_signer.length != MR_SIGNER_LENGTH){
            res.send(_result(400, `mr_enclave length must be ${MR_ENCLAVE_LENGTH}.`))
            return
        }
        let policyId = uuidv4();
        const createTime = new Date().getTime()
        await DB.insert({
            _id: `quote_policy:${policyId}`,
            appid,
            policyId,
            mr_enclave,
            mr_signer,
            createTime
        })
        let result = {
            policyId
        }
        res.send(_result(200, 'Upload quote policy success.', result))
        return
    } catch (e) {
        console.info('uploadQuotePolicy :: ', e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * query a quote policy information by policyid.
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}policyId(String) : a policy ID. eg. '15ca0dd5-2d34-4221-a708-3171ffe6****'
 * @returns {Object}
 *          ==> {r}policyId(String) : a policy ID. eg. '15ca0dd5-2d34-4221-a708-3171ffe6****'
 *          ==> {r}mr_enclave(String) : stores the hash value of the enclave measurement. eg. '870c42c59bc74c7ad22869411709e4f78ac3c76add6693bb43296b03362e5038'
 *          ==> {r}mr_signer(String) : stores the hash value of the enclave author’s public key. eg. 'c30446b4be9baf0f69728423ea613ef81a63e72acf7439fa0549001fd5482835'
 */
const getQuotePolicy = async (res, appid, payload, DB) => {
    try {
        const { policyId } = payload
        if (!checkStringParam(policyId, true, UUID_LENGTH )) {
            res.send(_result(400, `policyId cannot be empty, must be string and length not more than ${UUID_LENGTH}.`))
            return
        }
        if (!check_UUID_format(policyId)) {
            res.send(_result(400, 'policyId format wrong.'))
            return
        }

        let result = {
            policyId
        }
        const query = {
            selector: {
                appid,
                policyId
            },
            fields: ['mr_enclave', 'mr_signer', 'createTime'],
            limit: 1
        }
        let quote_policy_res = await DB.partitionedFind('quote_policy', query)
        if (quote_policy_res.docs.length > 0) {
            result['mr_enclave'] = quote_policy_res.docs[0].mr_enclave
            result['mr_signer'] = quote_policy_res.docs[0].mr_signer
            result['createTime'] = quote_policy_res.docs[0].createTime
        }

        res.send(_result(200, 'Query quote policy success.', result))
        return
    } catch (e) {
        console.info('getQuotePolicy :: ', e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 *
 */
module.exports = {
    generateQuote,
    verifyQuote,
    uploadQuotePolicy,
    getQuotePolicy
}