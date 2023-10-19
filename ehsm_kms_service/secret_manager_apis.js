const crypto = require('crypto')
const logger = require('./logger')
const { v4: uuidv4 } = require('uuid')
const {
    Definition
} = require('./constant')
const {
    napi_result,
    _result,
    base64_encode,
    base64_decode
} = require('./function')
const { KMS_ACTION } = require('./apis')
const {
    add_delete_task,
    remove_delete_task
} = require('./delete_secret_thread')

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
    if (encryptionKeyId === "" || encryptionKeyId === undefined) {
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
function calculateNextRotationDate(rotationInterval, createTime) {
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

/**
 * Force delete secret metadata and secret version data by appId and secretName
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} secretName : The name of the secret. eg. 'secretName01'
 * @returns {boolean}
 */
const forceDeleteData = async (DB, appid, secretName) => {
    try {
        //Query and delete the secret metadata
        const query_secret_metadata = {
            selector: {
                appid,
                secretName
            },
            fields: ['_id', '_rev'],
            limit: 1
        }
        let secret_metadata_res = await DB.partitionedFind('secret_metadata', query_secret_metadata)
        if (secret_metadata_res.docs.length > 0) {
            await DB.destroy(secret_metadata_res.docs[0]._id, secret_metadata_res.docs[0]._rev)
            //Query and delete the secret version data
            const query_secret_version_data = {
                selector: {
                    appid,
                    secretName
                },
                fields: ['_id', '_rev'],
            }
            let secret_version_data_res = await DB.partitionedFind('secret_version_data', query_secret_version_data)
            if (secret_version_data_res.docs.length > 0) {
                for (const secret_version_data_item of secret_version_data_res.docs) {
                    secret_version_data_item._deleted = true
                }
                await DB.bulk({ docs: secret_version_data_res.docs })
            }
            return true
        } else {
            return false
        }
    } catch (e) {
        logger.error(e)
        return false
    }
}

/**
 * Creates a secret and stores its initial version.
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}secretName(String [1~64]) : The name of the secret. eg. 'secretName01'
 *          ==> {r}secretData(String [1~4096]) : The value of the secret.
 *          ==> {o}encryptionKeyId(String [32]) : The ID of the CMK that is used to encrypt the secret value. eg. 0197ad2d-c4be-4948-996d-513c6f1e****
 *          ==> {o}description(String [1~4096]) : The description of the secret. eg. 'desc01'
 *          ==> {o}rotationInterval(String [0~5])[defalut='30d'] : The interval for automatic rotation. format: integer[unit],
 *                                               unit can be d (day), h (hour), m (minute), or s (second)
 *                                               eg. '30d'
 * @returns
 */
const createSecret = async (res, appid, DB, payload) => {
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
        const apikey_encrypt_res = napi_result(KMS_ACTION.cryptographic.Encrypt, res, { cmk: sm_masterKey, plaintext: secretData, aad: '' })
        // check encrypt status and get ciphertext
        if (!apikey_encrypt_res) {
            return
        }
        if (apikey_encrypt_res.code != 200) {
            res.send(apikey_encrypt_res)
            return
        }
        const { ciphertext } = apikey_encrypt_res.result

        //Next rotation time calculation
        if (rotationInterval != '' && rotationInterval != undefined) {
            nextRotationDate = calculateNextRotationDate(rotationInterval, createTime)
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
                secretData: ciphertext,
                createTime,
                versionStage: Definition.SM_SECRET_VERSION_STAGE_CURRENT
            }).then(() => {
                res.send(_result(200, `The ${base64_decode(secretName)} create success.`))
            }).catch((e3) => {
                logger.error(e3)
                res.send(_result(500, 'Server internal error, please contact the administrator.'))
                return
            })
        }).catch((e2) => {
            logger.error(e2)
            res.send(_result(500, 'Server internal error, please contact the administrator.'))
            return
        })
    } catch (e1) {
        logger.error(e1)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * Update the description of a secret
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}secretName(String [1~64]) : The name of the secret. eg. 'secretName01'
 *          ==> {o}description(String [1~4096]) : The description of the secret. eg. 'desc01'
 * @returns
 */
const updateSecretDesc = async (res, appid, DB, payload) => {
    try {
        //get and check param in payload
        let secretName = getParam_String(payload, 'secretName')
        let description = getParam_String(payload, 'description')

        //Query the description through secret name and update the description
        const secret_name_query = {
            selector: {
                appid,
                secretName
            },
            limit: 1,
        }
        const secret_metadata_res = await DB.partitionedFind('secret_metadata', secret_name_query)
        if (secret_metadata_res.docs.length == 0) {
            res.send(_result(400, 'Cannot find secretName'))
            return
        } else if (secret_metadata_res.docs[0].deleteTime != null) {
            res.send(_result(400, 'Can not modify a deleted secret.'))
            return
        } else {
            // update description
            secret_metadata_res.docs[0].description = description
            DB.insert(secret_metadata_res.docs[0])
            res.send(_result(200, 'Update secret description success.'))
            return
        }

    } catch (e) {
        logger.error(e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * stores the secret value of a new version into a secret object.
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}secretName(String [1~64]) : The name of the secret. eg. 'secretName01'
 *          ==> {r}secretData(String [1~4096]) : The value of the secret. eg. 'secretData01'
 * @returns
 */
const putSecretValue = async (res, appid, DB, payload) => {
    try {
        //get and check Param in payload
        let secretName = getParam_String(payload, 'secretName')
        let secretData = getParam_String(payload, 'secretData')
        const createTime = new Date().getTime()
        let sm_masterKey
        let encryptionKeyId
        let versionId

        //query SM_Masterkey and encrypt secretData
        const query_secertName = {
            selector: {
                appid,
                secretName
            },
            limit: 1
        }
        const secret_metadata_res = await DB.partitionedFind('secret_metadata', query_secertName)
        if (secret_metadata_res.docs.length == 0) {
            res.send(_result(400, 'Can not find secretName'))
            return
        } else if (secret_metadata_res.docs[0].deleteTime != null) {
            res.send(_result(400, 'Can not put value for a deleted secret.'))
            return
        } else {
            if (secret_metadata_res.docs[0].encryptionKeyId == undefined) {
                encryptionKeyId = ""
            }
            else {
                encryptionKeyId = secret_metadata_res.docs[0].encryptionKeyId
            }
        }
        retCMK = await get_SM_Masterkey(DB, appid, encryptionKeyId)
        if (retCMK.isFind) {
            sm_masterKey = retCMK.sm_masterKey
        } else {
            res.send(_result(400, retCMK.msg))
            return
        }

        const apikey_encrypt_res = napi_result(KMS_ACTION.cryptographic.Encrypt, res, { cmk: sm_masterKey, plaintext: secretData, aad: '' })
        // check encrypt status and get ciphertext
        if (!apikey_encrypt_res) {
            return
        }
        if (apikey_encrypt_res.code != 200) {
            res.send(apikey_encrypt_res)
            return
        }
        const { ciphertext } = apikey_encrypt_res.result

        //Search the old version by appid, secretName, versionStage, deletedFlag 
        //change old version stage and add a new version
        const query_version_stage = {
            selector: {
                appid,
                secretName,
                versionStage: Definition.SM_SECRET_VERSION_STAGE_CURRENT,
            },
            limit: 1
        }
        const version_stage_res = await DB.partitionedFind('secret_version_data', query_version_stage)
        if (version_stage_res.docs.length > 0) {
            versionId = version_stage_res.docs[0].versionId + 1
            version_stage_res.docs[0].versionStage = Definition.SM_SECRET_VERSION_STAGE_PREVIOUS
            await DB.insert(version_stage_res.docs[0])
            await DB.insert({
                _id: `secret_version_data:${uuidv4()}`,
                appid,
                secretName,
                versionId,
                secretData: ciphertext,
                createTime,
                versionStage: Definition.SM_SECRET_VERSION_STAGE_CURRENT
            })
            res.send(_result(200, `The ${base64_decode(secretName)} new version put success.`))
            return
        } else {
            res.send(_result(400, 'Current secretname cannot find previous version'))
            return
        }
    } catch (e) {
        logger.error(e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * Queries all versions of a secret. Maximum 4000 line 
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}secretName(String [1~64]) : The name of the secret. eg. 'secretName01'
 * @returns {Object}
 *          ==> {r}secretName(String) : The name of the secret. eg. 'secretName01'
 *          ==> {r}totalCount(int) : The number of returned secrets. eg. 15
 *          ==> {r}versionIds(Array[Object]) : The list of secret versions.
 *                  Object ==> {r}versionId(int) : The version number of the secret value. eg. 12
 *                  Object ==> {r}createTime(long) : The time when the secret was created, millisecond unit. eg. 1659519772925
 */
const listSecretVersionIds = async (res, appid, DB, payload) => {
    try {
        // get and check parameter 
        let secretName = getParam_String(payload, 'secretName')

        // return result
        let result = {
            'secretName': base64_decode(secretName),
            'totalCount': 0,
            'versionIds': []
        }

        // check secret is not deleted
        const secret_name_query = {
            selector: {
                appid,
                secretName,
                deleteTime: { "$eq": null }
            },
            fields: ['appid', 'secretName'],
            limit: 1,
        }
        let secret_name_result = await DB.partitionedFind('secret_metadata', secret_name_query)
        if (secret_name_result.docs.length > 0) {
            // search secret_version_data, Maximum 4000 line 
            const query = {
                selector: {
                    appid: appid,
                    secretName: secretName,
                },
                fields: ['versionId', 'createTime'],
                limit: 4000,
            }
            let secret_version_data_result = await DB.partitionedFind('secret_version_data', query)

            // build result
            if (secret_version_data_result.docs.length > 0) {
                result.totalCount = secret_version_data_result.docs.length
                for (const doc of secret_version_data_result.docs) {
                    let secretVersion = {};
                    secretVersion['versionId'] = doc['versionId']
                    secretVersion['createTime'] = doc['createTime']
                    result.versionIds.push(secretVersion)
                }
            }
        }

        res.send(_result(200, 'List secret versionIds success.', result))
        return
    } catch (e) {
        logger.error(e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * Queries all secrets created by your appid. Maximum 4000 line 
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {o}secretName(String [1~64]) : The name of the secret. eg. 'secretName01'
 * @returns {Object}
 *          ==> {r}totalCount(int) : The number of returned secrets. eg. 15
 *          ==> {r}secretList(Array[Object]) : The list of secrets.
 *                  Object ==> {r}secretName(String) : The name of the secret. eg. 'secretName01'
 *                  Object ==> {r}description(String) : The description of the secret. eg. 'desc01'
 *                  Object ==> {r}createTime(long) : The time when the secret was created, millisecond unit. eg. 1659519772925
 *                  Object ==> {o}plannedDeleteTime(long) : The time when the secret is scheduled to be deleted, millisecond unit. eg. 1659519772925
 */
const listSecrets = async (res, appid, DB, payload) => {
    try {
        // get and check parameter 
        let secretName = getParam_String(payload, 'secretName')
        // build selector for search secret_metadata
        let selector = {
            appid: appid
        }
        if (secretName != '' && secretName != undefined) {
            selector['secretName'] = secretName
        }

        // search secret_metadata, Maximum 4000 line 
        const query = {
            selector,
            fields: ['secretName', 'description', 'createTime', 'plannedDeleteTime'],
            limit: 4000,
        }
        let secret_metadata_result = await DB.partitionedFind('secret_metadata', query)

        // build result
        let result = {
            'totalCount': 0,
            'secretList': []
        }
        if (secret_metadata_result.docs.length > 0) {
            result.totalCount = secret_metadata_result.docs.length
            for (const doc of secret_metadata_result.docs) {
                let secret = {};
                secret['secretName'] = base64_decode(doc['secretName'])
                if (doc['description']) {
                    secret['description'] = base64_decode(doc['description'])
                }
                secret['createTime'] = doc['createTime']
                if (doc['plannedDeleteTime']) {
                    secret['plannedDeleteTime'] = doc['plannedDeleteTime']
                }
                result.secretList.push(secret)
            }
        }

        res.send(_result(200, 'List secrets success.', result))
        return
    } catch (e) {
        logger.error(e)
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
const describeSecret = async (res, appid, DB, payload) => {
    try {
        // get and check parameter 
        let secretName = getParam_String(payload, 'secretName')

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
            if (doc['description']) {
                result['description'] = base64_decode(doc['description'])
            }
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

        res.send(_result(200, 'Describe secrets success.', result))
        return
    } catch (e) {
        logger.error(e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * Force delete secret or schedule a time to delete secret
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}secretName(String [1~64]) : The name of the secret. eg. 'secretName01'
 *          ==> {o}recoveryPeriod(Number [1~365])[defalut=30]: Specifies the recovery period of the secret,The unit is day, if you do not forcibly delete it.
 *               eg. 50 
 *          ==> {o}forceDelete(String [true/false])[defalut='false']: Specifies whether to forcibly delete the secret.
 *                 If this parameter is set to true, the secret cannot be recovered. eg. 'true'
 * @returns
 */
const deleteSecret = async (res, appid, DB, payload) => {
    try {
        //get and check Param in payload
        const deleteTime = new Date().getTime()
        let secretName = getParam_String(payload, 'secretName')
        let recoveryPeriod = payload['recoveryPeriod']
        let forceDelete = payload['forceDelete']


        if (forceDelete != '' && forceDelete != undefined) {
            if (forceDelete.toUpperCase() != 'TRUE' && forceDelete.toUpperCase() != 'FALSE') {
                res.send(_result(400, 'The forceDelete must be true or false'))
                return
            }
        }

        // if recoveryPeriod is undefinied, default value is DEFAULT_DELETE_RECOVERY_DAYS
        if (recoveryPeriod == '' || recoveryPeriod == undefined) {
            recoveryPeriod = Definition.DEFAULT_DELETE_RECOVERY_DAYS
        }

        // calculate planned delete time
        let plannedDeleteTime = deleteTime + 24 * 60 * 60 * 1000 * recoveryPeriod

        //Query and change the secret metadata
        const query_matadata = {
            selector: {
                appid,
                secretName
            },
            limit: 1
        }
        let secret_metadata_res = await DB.partitionedFind('secret_metadata', query_matadata)
        if (secret_metadata_res.docs.length > 0) {
            if (forceDelete == 'true') {
                //Force delete secret metadata and secret version data by appId and secretName
                if (await forceDeleteData(DB, appid, secretName)) {
                    remove_delete_task(secretName, appid)
                    res.send(_result(200, `The ${base64_decode(secretName)} delete success`))
                    return
                } else {
                    res.send(_result(400, 'Force delete failed'))
                    return
                }
            } else {
                //update secret metadata
                secret_metadata_res.docs[0].deleteTime = deleteTime
                secret_metadata_res.docs[0].plannedDeleteTime = plannedDeleteTime
                await DB.insert(secret_metadata_res.docs[0])
                add_delete_task(DB, appid, secretName, plannedDeleteTime)
                res.send(_result(200, `The ${base64_decode(secretName)} will be deleted after ${recoveryPeriod} days.`))
                return
            }
        } else {
            res.send(_result(400, 'Delete error, Can not find the secretName'))
            return
        }
    } catch (e) {
        logger.error(e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * Obtains a secret value.
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}secretName(String [1~64]) : The name of the secret. eg. 'secretName01'
 *          ==> {o}versionId(int [> 0]) : The version number of the secret value. eg. 12
 * @returns {Object}
 *          ==> {o}secretName(String) : The name of the secret. eg. 'secretName01'
 *          ==> {o}secretData(String) : The secret value. eg. 'secretData01'
 *          ==> {o}versionId(int) : The version number of the secret value. eg. 12
 *          ==> {o}createTime(long) : The time when the secret value was created, millisecond unit. eg. 1659519772925
 */
const getSecretValue = async (res, appid, DB, payload) => {
    try {
        // get and check parameter
        let secretName = getParam_String(payload, 'secretName')
        let versionId = payload['versionId']
        let selector;

        //query encryptionKeyId, just read undelete secret's value
        const query_encryptionKeyId = {
            selector: {
                appid,
                secretName,
                deleteTime: { "$eq": null }
            },
            fields: ['encryptionKeyId'],
            limit: 1,
        }
        const secret_metadata_res = await DB.partitionedFind('secret_metadata', query_encryptionKeyId)
        if (secret_metadata_res.docs.length == 0) {
            res.send(_result(400, `Can't find the ${base64_decode(secretName)}'s value.`))
            return
        }
        encryptionKeyId = secret_metadata_res.docs[0].encryptionKeyId

        // build selector for search CouchDB, if has versionId use it find, 
        // if not use versionStage = SM_SECRET_VERSION_STAGE_CURRENT
        if (versionId) {
            selector = {
                appid: appid,
                secretName: secretName,
                versionId: versionId
            }
        } else {
            selector = {
                appid: appid,
                secretName: secretName,
                versionStage: Definition.SM_SECRET_VERSION_STAGE_CURRENT
            }
        }

        // query secret_version_data
        const query = {
            selector,
            fields: ['secretData', 'versionId', 'createTime'],
            limit: 1,
        }
        let query_result = await DB.partitionedFind('secret_version_data', query)

        // build result
        let result = {}
        if (query_result.docs.length > 0) {
            let secretData = query_result.docs[0]['secretData']
            let createTime = query_result.docs[0]['createTime']
            versionId = query_result.docs[0]['versionId']

            // query SM_Masterkey
            let sm_masterKey
            let retCMK = await get_SM_Masterkey(DB, appid, encryptionKeyId)
            if (retCMK.isFind) {
                sm_masterKey = retCMK.sm_masterKey
            } else {
                res.send(_result(400, retCMK.msg))
                return
            }

            // decrypt secretData
            const secretData_decypt_result = napi_result(KMS_ACTION.cryptographic.Decrypt, res, { cmk: sm_masterKey, ciphertext: secretData, aad: '' })
            // check Decrypt status and get plaintext
            if (!secretData_decypt_result) {
                return
            }
            if (secretData_decypt_result.code != 200) {
                res.send(secretData_decypt_result)
                return
            }

            result['secretName'] = base64_decode(secretName)
            result['secretData'] = base64_decode(secretData_decypt_result.result['plaintext'])
            result['versionId'] = versionId
            result['createTime'] = createTime
        }
        res.send(_result(200, 'successful', result))
        return
    } catch (e) {
        logger.error(e)
        res.send(_result(500, 'Server internal error, please contact the administrator.'))
        return
    }
}

/**
 * Restores a deleted secret.
 * @param {Object} res : response
 * @param {String} appid : appid of user
 * @param {Object} DB : database controller
 * @param {Object} payload
 *          ==> {r}secretName(String [1~64]) : The name of the secret. eg. 'secretName01'
 * @returns
 */
const restoreSecret = async (res, appid, DB, payload) => {
    try {
        let secretName = getParam_String(payload, 'secretName')

        //Query and change the secret metadata
        const query_matadata = {
            selector: {
                appid,
                secretName
            },
            limit: 1
        }
        let secret_metadata_res = await DB.partitionedFind('secret_metadata', query_matadata)
        if (secret_metadata_res.docs.length > 0) {
            //update secret metadata
            secret_metadata_res.docs[0].deleteTime = null
            secret_metadata_res.docs[0].plannedDeleteTime = null
            await DB.insert(secret_metadata_res.docs[0])
            //Delete the added thread by secretName
            remove_delete_task(secretName, appid)
            res.send(_result(200, `The ${base64_decode(secretName)} restore success.`))
            return
        } else {
            res.send(_result(400, 'Can not restore secret, the secretName not find.'))
            return
        }
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
    createSecret,
    updateSecretDesc,
    putSecretValue,
    listSecretVersionIds,
    listSecrets,
    describeSecret,
    deleteSecret,
    getSecretValue,
    restoreSecret,
    forceDeleteData
}