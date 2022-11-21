const logger = require('./logger')
const { v4: uuidv4 } = require('uuid')
const {
    Definition
} = require('./constant')
const {
    napi_result,
    _result,
    base64_encode,
    base64_decode,
    gen_hmac
} = require('./function')

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
        const challenge = payload['challenge']
        napi_res = napi_result(action, res, {challenge})
        napi_res && res.send(napi_res)
    } catch (e) {
        logger.error(e)
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
 *          ==> {o}policyId(String [36]) : quote policy ID. eg. '326f2049-56ab-474f-a1c0-516de230****'
 * @returns {Object}
 *          ==> {r}result(bool) : The result of quote verification. eg. 'true'
 *          ==> {r}nonce(bool) : The nonce in BASE64 string. eg. 'bm9uY2U='
 *          ==> {r}mr_enclave(String) : stores the hash value of the enclave measurement. eg. '870c42c59bc74c7ad22869411709e4f78ac3c76add6693bb43296b03362e5038'
 *          ==> {r}mr_signer(String) : stores the hash value of the enclave author’s public key. eg. 'c30446b4be9baf0f69728423ea613ef81a63e72acf7439fa0549001fd5482835'
 *          ==> {r}sign(String) : The HAMC sign of result and nonce calculated by the API Key. eg. 'T4DRCEZAPLBbb+d3ObD∗∗∗'
 */
const verifyQuote = async (res, appid, payload, DB, action) => {
    try {
        const quote = payload['quote']
        const nonce = payload['nonce']
        const policyId = payload['policyId']
        let mr_enclave = ''
        let mr_signer = ''
        if (policyId != '' && policyId != undefined) {
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
        }
        napi_res = napi_result(action, res, {quote, mr_signer, mr_enclave, nonce})
        if (napi_res) {
            if (mr_enclave != '') {
                napi_res.result.mr_enclave = mr_enclave
            }
            if (mr_signer != '') {
                napi_res.result.mr_signer = mr_signer
            }
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
        logger.error(e)
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
        const mr_enclave = payload['mr_enclave']
        const mr_signer = payload['mr_signer']
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
        logger.error(e)
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
        const policyId = payload['policyId']
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
        logger.error(e)
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