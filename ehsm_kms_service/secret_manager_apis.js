const crypto = require('crypto')
const logger = require('./logger')
const { v4: uuidv4 } = require('uuid')
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

// get a string parameter from payload and base64 if you need
function getParam_String(payload, key, needBase64) {
    if (needBase64 == undefined) {
        needBase64 = true;
    }
    let val = payload[key]
    if (val != undefined) {
        val = String(val)
        if (needBase64) {
            val = base64_encode(val)
        }
    }
    return val
}

//check param is string and required
function checkStringParam(param, required) {
    if (param == '' || param == undefined) {
        if (required) {
            return false
        } else {
            return true
        }
    } else {
        if (typeof (param) == 'string') {
            return true
        } else {
            return false
        }
    }
}

//check encryptionKeyId format
function check_encryptionKeyId_format(encryptionKeyId) {
    if (encryptionKeyId != '' && encryptionKeyId != undefined) {
        if (!((/^([a-z\d]{8}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{4}-[a-z\d]{12})$/).test(encryptionKeyId))) {
            return false
        }
    }
    return true
}

//check rotationInterval format
function check_rotationInterval_format(rotationInterval) {
    if (rotationInterval != '' && rotationInterval != undefined) {
        if (!((/^(\d{1,4}[d,h,m,s]{1})$/).test(rotationInterval))) {
            return false
        }
    }
    return true
}

//KeyId query
const queryKeyId = (appid, keyid) => {
    return {
        selector: {
            creator: appid,
            keyid
        },
        fields: ['keyBlob'],
        limit: 1
    }
}

//Defaultcmk query
const queryDefaultCMK = (appid) => {
    return {
        selector: {
            appid
        },
        fields: ['sm_default_cmk'],
        limit: 1
    }
}

//Calculate nextrotationdate
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
        let keyBlob = ''
        let nextRotationDate = ''
        if (!checkStringParam(secretData, true)) {
            res.send(_result(400, 'secretData cannot be empty and must be string'))
            return
        }
        if (!checkStringParam(secretName, true)) {
            res.send(_result(400, 'secretName cannot be empty and must be string'))
            return
        }
        if (!checkStringParam(description, false)) {
            res.send(_result(400, 'description must be string'))
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

        //Query keyblob through encryptionkeyid, encrypt secretdata through keyblob
        if (encryptionKeyId != '' && typeof (encryptionKeyId) == 'string') {
            let key_id_res = await DB.partitionedFind('cmk', queryKeyId(appid, encryptionKeyId))
            if (key_id_res.docs.length == 0) {
                res.send(_result(400, 'Cannot find key id'))
                return
            } else {
                keyBlob = key_id_res.docs[0].keyBlob
            }
        } else if (encryptionKeyId == "" || encryptionKeyId == undefined) {
            let default_cmk_res = await DB.partitionedFind('user_info', queryDefaultCMK(appid))
            if (default_cmk_res.docs.length == 0) {
                res.send(_result(400, 'Cannot find default CMK'))
                return
            }
            keyBlob = default_cmk_res.docs[0].sm_default_cmk
        } else {
            res.send(_result(400, 'internal error, sm_default_CMK always exists, this should not happen'))
            return
        }
        const apikey_encrypt_res = napi_result(cryptographic_apis.Encrypt, res, [keyBlob, secretData, ''])
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
                createTime
            }).then(() => {
                res.send(_result(200, `The ${base64_decode(secretName)} create success.`))
            }).catch((e) => {
                res.send(_result(400, 'create secret_version_data failed', e))
                return
            })
        }).catch((e) => {
            res.send(_result(400, 'secret_metadata failed', e))
            return
        })
    } catch (e) {
        res.send(_result(400, 'create secret failed', e))
    }
}

//update the description of secret
const updateSecretDesc = async (res, appid, payload, DB) => {
    //get and check param in payload
    let secretName = getParam_String(payload, 'secretName')
    let description = getParam_String(payload, 'description')
    if (!checkStringParam(secretName, true)) {
        res.send(_result(400, 'secretName cannot be empty and must be string'))
        return
    }
    if (!checkStringParam(description, true)) {
        res.send(_result(400, 'description cannot be empty and must be string'))
        return
    }

    //Query the description through secret name and update the description
    const secret_name_query = {
        selector: {
            appid,
            secretName
        },
        fields: [
            '_id',
            '_rev',
            'appid',
            'secretName',
            'encryptionKeyId',
            'description',
            'createTime',
            'deleteTime',
            'plannedDeleteTime',
            'rotationInterval',
            'lastRotationDate',
            'nextRotationDate'
        ],
        limit: 1,
    }
    await DB.partitionedFind('secret_metadata', secret_name_query)
        .then((secret_metadata_res) => {
            if (secret_metadata_res.docs.length > 0) {
                secret_metadata_res.docs[0].description = description
                DB.insert(secret_metadata_res.docs[0])
                    .then(() => {
                        res.send(_result(200, 'update secret seccess'))
                    })
                    .catch((err) => {
                        console.info('createSecret :: ', err)
                        res.send(_result(500, 'Server internal error, please contact the administrator.'))
                    })
            } else {
                res.send(_result(400, 'cannot find secretName'))
                return
            }
        })
        .catch((err) => {
            console.info('createSecret :: ', err)
            res.send(_result(500, 'Server internal error, please contact the administrator.'))
        })
}

/**
 *
 */
module.exports = {
    createSecret,
    updateSecretDesc
}