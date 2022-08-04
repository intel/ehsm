const crypto = require('crypto')
const logger = require('./logger')
const { v4: uuidv4 } = require('uuid')
const {
    SM_SECRET_VERSION_STAGE_CURRENT,
    SM_SECRET_VERSION_STAGE_PREVIOUS,
    SECRETNAME_LENGTH_MAX,
    SECRETDATA_LENGTH_MAX,
    DESCRIPTION_LENGTH_MAX
} = require('./constant')
const {
    napi_result,
    _result,
    base64_encode,
    base64_decode
} = require('./function')
const {
    cryptographic_apis,
} = require('./apis')
const ehsm_napi = require('./ehsm_napi')

/**
 * get a string parameter from payload and base64 if you need
 * @param {Object} payload : a json object
 * @param {String} key : the key of payload
 * @param {boolean} needBase64 [defalut=true] : The return value needs Base64 encoding flag
 * @returns {String}
 */
function getParam_String(payload, key, needBase64 = true) {
    let val = payload[key]
    if (val != undefined) {
        val = String(val)
        if (needBase64) {
            val = base64_encode(val)
        }
    }
    return val
}

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
 * check encryptionKeyId format
 * @param {String} encryptionKeyId : The ID of CMK, eg. 0197ad2d-c4be-4948-996d-513c6f1e****
 * @returns {boolean}
 */
function check_encryptionKeyId_format(encryptionKeyId) {
    if (encryptionKeyId != '' && encryptionKeyId != undefined) {
        if (!((/^([a-z\d]{8}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{12})$/).test(encryptionKeyId))) {
            return false
        }
    }
    return true
}

/**
 * check rotationInterval format
 * @param {String [0~5]} rotationInterval : The interval for automatic rotation. 
 *                                      format: integer[unit],
 *                                      unit can be d (day), h (hour), m (minute), or s (second)
 *                                      eg. '30d'
 * @returns {boolean}
 */
function check_rotationInterval_format(rotationInterval) {
    if (rotationInterval != '' && rotationInterval != undefined) {
        if (!((/^(\d{1,4}[d,h,m,s]{1})$/).test(rotationInterval))) {
            return false
        }
    }
    return true
}

/**
 * Query SM_MasterKey through encryptionkeyid, if encryptionKeyId is undefined, will be return default CMK of appid.
 * @param {Object} DB : database controller
 * @param {String} appid : appid of user
 * @param {String} encryptionKeyId [defalut=undefined] : The ID of CMK, eg. 0197ad2d-c4be-4948-996d-513c6f1e****
 * @returns {Ojbect}
 *          ==> isFind(boolean) : Whether to query the flag of CMK
 *          ==> sm_masterKey(String) : blob string of CMK
 *          ==> msg(String) : If isfind is false, MSG will record some messages that the reason is not found
 */
const get_SM_Masterkey = async (DB, appid, encryptionKeyId) => {
    let ret = {
        isFind: false,
        sm_masterKey: undefined,
        msg: ''
    }
    if (encryptionKeyId == "" || encryptionKeyId == undefined) {
        // query default SM_MasterKey
        const query = {
            selector: {
                appid
            },
            fields: ['sm_default_cmk'],
            limit: 1
        }
        let res = await DB.partitionedFind('user_info', query)
        if (res.docs.length == 0) {
            ret.msg = 'Cannot find default CMK.'
        } else {
            ret.isFind = true
            ret.sm_masterKey = res.docs[0].sm_default_cmk
        }
    } else if (typeof (encryptionKeyId) == 'string') {
        // query SM_MasterKey by encryptionKeyId
        if (check_encryptionKeyId_format(encryptionKeyId)) {
            const query = {
                selector: {
                    creator: appid,
                    keyid: encryptionKeyId
                },
                fields: ['keyBlob'],
                limit: 1
            }
            let res = await DB.partitionedFind('cmk', query)
            if (res.docs.length == 0) {
                ret.msg = 'Cannot find cmk by keyid.'
            } else {
                ret.isFind = true
                ret.sm_masterKey = res.docs[0].keyBlob
            }
        } else {
            ret.msg = 'The encryptionKeyId format error.'
        }
    } else {
        ret.msg = 'Wrong parameter, please check your encryptionKeyId.'
    }
    return ret
}

/**
 * Calculate the time of the next rotation
 * @param {string} rotationInterval : 
 * @param {long} createTime : base time, millisecond unit. eg. 1659519772925
 * @returns {long} nextRotationDate = createTime + rotationInterval, millisecond unit. eg. 1659519772925
 */
function calculateRotationSperate(rotationInterval, createTime) {
    let timenum = rotationInterval.substring(0, rotationInterval.length - 1)
    let unit = rotationInterval.substring(rotationInterval.length - 1, rotationInterval.length)
    let nextRotationDate = ''
    switch (unit) {
        case (unit = 'd'):
            nextRotationDate = timenum * 24 * 60 * 60 * 1000 + createTime
            break
        case (unit = 'h'):
            nextRotationDate = timenum * 60 * 60 * 1000 + createTime
            break
        case (unit = 'm'):
            nextRotationDate = timenum * 60 * 1000 + createTime
            break
        case (unit = 's'):
            nextRotationDate = timenum * 1000 + createTime
            break
    }
    let interval = nextRotationDate - createTime
    if (6 * 60 * 60 * 1000 > interval || interval > 8760 * 60 * 60 * 1000) {
        return false
    }
    return nextRotationDate
}

//create Secret
const createSecret = async (res, appid, payload, DB) => {
    try {
        //get and check param in payload
        let secretData = getParam_String(payload, 'secretData')
        let secretName = getParam_String(payload, 'secretName')
        let encryptionKeyId = getParam_String(payload, 'encryptionKeyId', false)
        let description = getParam_String(payload, 'description')
        let rotationInterval = getParam_String(payload, 'rotationInterval', false)
        const createTime = new Date().getTime()
        let sm_masterKey
        let nextRotationDate
        if (!checkStringParam(secretData, true, SECRETDATA_LENGTH_MAX)) {
            res.send(_result(400, 'secretData cannot be empty, must be string and length not more than 4096'))
            return
        }
        if (!checkStringParam(secretName, true, SECRETNAME_LENGTH_MAX)) {
            res.send(_result(400, 'secretName cannot be empty, must be string and length not more than 64'))
            return
        }
        if (!checkStringParam(description, false, DESCRIPTION_LENGTH_MAX)) {
            res.send(_result(400, 'description must be string and length not more than 4096'))
            return
        }
        if (!checkStringParam(rotationInterval, false)) {
            res.send(_result(400, 'rotationInterval must be string'))
            return
        }
        if (!check_encryptionKeyId_format(encryptionKeyId)) {
            res.send(_result(400, 'encryptionKeyId format wrong'))
            return
        }
        if (!check_rotationInterval_format(rotationInterval)) {
            res.send(_result(400, 'rotationInterval format wrong'))
            return
        }

        //Query whether the secretname is duplicate
        const secret_name_query = {
            selector: {
                appid,
                secretName
            },
            fields: ['appid', 'secretName'],
            limit: 1,
        }
        let secret_name_result = await DB.partitionedFind('secret_metadata', secret_name_query)
        if (secret_name_result.docs.length > 0) {
            res.send(_result(400, 'Secret name already exists, cannot use the same secret name'))
            return
        }

        // query SM_Masterkey and encrypt secretData
        retCMK = await get_SM_Masterkey(DB, appid, encryptionKeyId)
        if (retCMK.isFind) {
            sm_masterKey = retCMK.sm_masterKey
        } else {
            res.send(_result(400, retCMK.msg))
            return
        }
        const apikey_encrypt_res = napi_result(cryptographic_apis.Encrypt, res, [sm_masterKey, secretData, ''])
        const { ciphertext } = apikey_encrypt_res.result

        //Next rotation time calculation
        if (rotationInterval != '' && rotationInterval != undefined) {
            nextRotationDate = calculateRotationSperate(rotationInterval, createTime)
            if (!nextRotationDate) {
                res.send(_result(400, 'The rotation time is less than 6 hours or more than 8760 hours'))
                return
            }
        }

        //Insert form
        DB.insert({
            _id: `secret_metadata:${uuidv4()}`,
            appid,
            secretName,
            encryptionKeyId,
            description,
            createTime,
            deleteTime: null,
            plannedDeleteTime: null,
            rotationInterval,
            lastRotationDate: '',
            nextRotationDate
        }).then(() => {
            DB.insert({
                _id: `secret_version_data:${uuidv4()}`,
                appid,
                secretName,
                versionId: 1,
                deletedFlag: false,
                secretData: ciphertext,
                createTime,
                versionStage: SM_SECRET_VERSION_STAGE_CURRENT
            }).then(() => {
                res.send(_result(200, `The ${base64_decode(secretName)} create success.`))
            }).catch((e) => {
                console.info('createSecret :: ', e)
                res.send(_result(500, 'Server internal error, please contact the administrator.'))
                return
            })
        }).catch((e) => {
            console.info('createSecret :: ', e)
            res.send(_result(500, 'Server internal error, please contact the administrator.'))
            return
        })
    } catch (e) {
        console.info('createSecret :: ', e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * Obtains the metadata of a secret.
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}secretName(String [1~64]) : The name of the secret. eg. 'secretName01'
 * @returns {Object}
 *          ==> {o}secretName(String) : The name of the secret. eg. 'secretName01'
 *          ==> {o}description(String) : The description of the secret. eg. 'desc01'
 *          ==> {o}createTime(long) : The time when the secret was created. eg. 1659519772925
 *          ==> {o}plannedDeleteTime(long) : The time when the secret is scheduled to be deleted. eg. 1659519772925
 *          ==> {o}rotationInterval(String) : The interval for automatic rotation. 
 *                                      format: integer[unit],
 *                                      unit can be d (day), h (hour), m (minute), or s (second)
 *                                      eg. '30d'
 *          ==> {o}lastRotationDate(long) : The time when the last rotation was performed. eg. 1659519772925
 *          ==> {o}nextRotationDate(long) : The time when the next rotation will be performed. eg. 1659519772925
 */
const describeSecret = async (res, appid, payload, DB) => {
    try {
        // get and check parameter 
        let secretName = getParam_String(payload, 'secretName')
        if (!checkStringParam(secretName, true, SECRETNAME_LENGTH_MAX)) {
            res.send(_result(400, `secretName cannot be empty, must be string and length not more than ${SECRETNAME_LENGTH_MAX}`))
            return
        }

        // search secret_metadata 
        const query = {
            selector: {
                appid,
                secretName
            },
            fields: ['secretName', 'description', 'createTime', 'plannedDeleteTime', 'rotationInterval', 'lastRotationDate', 'nextRotationDate'],
            limit: 1,
        }
        let secret_metadata_result = await DB.partitionedFind('secret_metadata', query)

        // build result
        let result = {}
        if (secret_metadata_result.docs.length > 0) {
            const doc = secret_metadata_result.docs[0]
            result['secretName'] = base64_decode(doc['secretName'])
            result['description'] = base64_decode(doc['description'])
            result['createTime'] = doc['createTime']
            if (doc['plannedDeleteTime']) {
                result['plannedDeleteTime'] = doc['plannedDeleteTime']
            }
            if (doc['rotationInterval']) {
                result['rotationInterval'] = doc['rotationInterval']
                result['lastRotationDate'] = doc['lastRotationDate']
                result['nextRotationDate'] = doc['nextRotationDate']
            }
        }

        res.send(_result(200, 'describe secrets success.', result))
        return
    } catch (e) {
        console.info('describeSecrets :: ', e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 *
 */
module.exports = {
    createSecret,
    describeSecret
}