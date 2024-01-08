const { KMS_ACTION } = require('./apis')
const YAML = require('yamljs')
const logger = require('./logger')
const Definition = {
    MAX_TIME_STAMP_DIFF: 10 * 60 * 1000,
    NONCE_CACHE_TIME: 10 * 60 * 1000 * 2, // MAX_TIME_STAMP_DIFF * 2
    TIMESTAMP_LEN: 13,
    CMK_EFFECTIVE_DURATION: 1 * 365 * 24 * 60 * 60 * 1000,
    CMK_LOOP_CLEAR_TIME: 24 * 60 * 60 * 1000,
    CMK_EXPIRE_TIME_EXPAND: 10 * 24 * 60 * 60 * 1000,
    CMK_LOOP_CLEAR_EXECUTION_TIME: 3,
    SM_SECRET_VERSION_STAGE_CURRENT: 1,
    SM_SECRET_VERSION_STAGE_PREVIOUS: 0,
    DEFAULT_DELETE_RECOVERY_DAYS: 30,
    MAX_NONCE_LEN: 64,
    FFI_BUFFER_SIZE: 10000,
    TOKEN_LOOP_CLEAR_TIME: 12 * 60 * 60 * 1000,
    IMPORT_TOKEN_EFFECTIVE_DURATION: 24 * 60 * 60 * 1000
}

const ehsm_keySpec_t = {
    EH_AES_GCM_128: 1,
    EH_AES_GCM_192: 2,
    EH_AES_GCM_256: 3,
    EH_RSA_2048: 10,
    EH_RSA_3072: 11,
    EH_RSA_4096: 12,
    EH_EC_P224: 20,
    EH_EC_P256: 21,
    EH_EC_P256K: 22,
    EH_EC_P384: 23,
    EH_EC_P521: 24,
    EH_SM2: 30,
    EH_SM4_CTR: 31,
    EH_SM4_CBC: 32,
    EH_HMAC: 40
}

const ehsm_keyorigin_t = {
    EH_INTERNAL_KEY: 1,
    EH_EXTERNAL_KEY: 2
}

const ehsm_padding_mode_t = {
    EH_PAD_NONE: 0,
    EH_RSA_PKCS1: 1,
    EH_RSA_PKCS1_PSS: 2,
    EH_RSA_PKCS1_OAEP: 3
}

const ehsm_keyusage_t = {
    EH_KEYUSAGE_ENCRYPT_DECRYPT: 1,
    EH_KEYUSAGE_SIGN_VERIFY: 2
}

const ehsm_message_type_t = {
    EH_RAW: 1,
    EH_DIGEST: 2
}

const ehsm_digest_mode_t = {
    EH_SHA_224: 1,
    EH_SHA_256: 2,
    EH_SHA_384: 3,
    EH_SHA_512: 4,
    EH_SM3: 5
}

const ehsm_action_t = {
    EH_INITIALIZE: 0,
    EH_FINALIZE: 1,
    [KMS_ACTION.cryptographic.CreateKey]: 2,
    [KMS_ACTION.cryptographic.Encrypt]: 3,
    [KMS_ACTION.cryptographic.Decrypt]: 4,
    [KMS_ACTION.cryptographic.AsymmetricEncrypt]: 5,
    [KMS_ACTION.cryptographic.AsymmetricDecrypt]: 6,
    [KMS_ACTION.cryptographic.Sign]: 7,
    [KMS_ACTION.cryptographic.Verify]: 8,
    [KMS_ACTION.cryptographic.GenerateDataKey]: 9,
    [KMS_ACTION.cryptographic.GenerateDataKeyWithoutPlaintext]: 10,
    [KMS_ACTION.cryptographic.ExportDataKey]: 11,
    [KMS_ACTION.cryptographic.GetPublicKey]: 12,
    [KMS_ACTION.common.GetVersion]: 13,
    [KMS_ACTION.enroll.Enroll]: 14,
    [KMS_ACTION.remote_attestation.GenerateQuote]: 15,
    [KMS_ACTION.remote_attestation.VerifyQuote]: 16,
    [KMS_ACTION.common.GenHmac]: 17,
    [KMS_ACTION.common.GenTokenHmac]: 18,
    [KMS_ACTION.cryptographic.ImportKeyMaterial]: 19,
    [KMS_ACTION.cryptographic.GetParametersForImport]: 20,
}

const kms_config = {
    service: {
        port: -1,
        run_mode: ""
    },
    database: {
        username: "",
        password: "",
        server: "",
        port: "",
        db: ""
    },
    openssl: {
        create_conf: {
            countryName: "",
            localityName: "",
            organizationName: "",
            organizationalUnitName: "",
            commonName: "",
            emailAddress: ""
        },
        exist: {
            key: "",
            crt: ""
        }
    }
}
const update_kms_config_by_json = (config, json) => {
    for (const key in json) {
        if (Object.hasOwnProperty.call(json, key)) {
            const element = json[key];
            if (typeof element == 'object' && element) {
                if (Object.hasOwnProperty.call(config, key)) {
                    update_kms_config_by_json(config[key], element)
                }
            } else {
                if (Object.hasOwnProperty.call(config, key)) {
                    config[key] = element
                }
            }
        }
    }
}
/**
 * To start KMS server, need to call this function to load the kms config first.
 */
const load_kms_config = () => {
    // load config from yaml
    update_kms_config_by_json(kms_config, JSON.parse(JSON.stringify(YAML.load('config.yml'))))

    // load config from env
    const {
        EHSM_CONFIG_COUCHDB_USERNAME,
        EHSM_CONFIG_COUCHDB_PASSWORD,
        EHSM_CONFIG_COUCHDB_SERVER,
        EHSM_CONFIG_COUCHDB_PORT,
        EHSM_CONFIG_COUCHDB_DB,
        EHSM_CONFIG_OPENSSL_KEY, // The datas of privatekey's content which in base64 encoding.
        EHSM_CONFIG_OPENSSL_CRT, // The datas of certificate's content which in base64 encoding.
        EHSM_CONFIG_OPENSSL_COUNTRYNAME,
        EHSM_CONFIG_OPENSSL_LOCALITYNAME,
        EHSM_CONFIG_OPENSSL_ORGANIZATIONNAME,
        EHSM_CONFIG_OPENSSL_ORGANIZATIONALUNITNAME,
        EHSM_CONFIG_OPENSSL_COMMONNAME,
        EHSM_CONFIG_OPENSSL_EMAILADDRESS
    } = process.env
    if (EHSM_CONFIG_COUCHDB_USERNAME) {
        kms_config.database.username = EHSM_CONFIG_COUCHDB_USERNAME
    }
    if (EHSM_CONFIG_COUCHDB_PASSWORD) {
        kms_config.database.password = EHSM_CONFIG_COUCHDB_PASSWORD
    }
    if (EHSM_CONFIG_COUCHDB_SERVER) {
        kms_config.database.server = EHSM_CONFIG_COUCHDB_SERVER
    }
    if (EHSM_CONFIG_COUCHDB_PORT) {
        kms_config.database.port = EHSM_CONFIG_COUCHDB_PORT
    }
    if (EHSM_CONFIG_COUCHDB_DB) {
        kms_config.database.db = EHSM_CONFIG_COUCHDB_DB
    }

    if (EHSM_CONFIG_OPENSSL_KEY) {
        kms_config.openssl.exist.key = EHSM_CONFIG_OPENSSL_KEY
    }
    if (EHSM_CONFIG_OPENSSL_CRT) {
        kms_config.openssl.exist.crt = EHSM_CONFIG_OPENSSL_CRT
    }
    if (EHSM_CONFIG_OPENSSL_COUNTRYNAME) {
        kms_config.openssl.create_conf.countryName = EHSM_CONFIG_OPENSSL_COUNTRYNAME
    }
    if (EHSM_CONFIG_OPENSSL_LOCALITYNAME) {
        kms_config.openssl.create_conf.localityName = EHSM_CONFIG_OPENSSL_LOCALITYNAME
    }
    if (EHSM_CONFIG_OPENSSL_ORGANIZATIONNAME) {
        kms_config.openssl.create_conf.organizationName = EHSM_CONFIG_OPENSSL_ORGANIZATIONNAME
    }
    if (EHSM_CONFIG_OPENSSL_ORGANIZATIONALUNITNAME) {
        kms_config.openssl.create_conf.organizationalUnitName = EHSM_CONFIG_OPENSSL_ORGANIZATIONALUNITNAME
    }
    if (EHSM_CONFIG_OPENSSL_COMMONNAME) {
        kms_config.openssl.create_conf.commonName = EHSM_CONFIG_OPENSSL_COMMONNAME
    }
    if (EHSM_CONFIG_OPENSSL_EMAILADDRESS) {
        kms_config.openssl.create_conf.emailAddress = EHSM_CONFIG_OPENSSL_EMAILADDRESS
    }

    // load config from arg
    for (const arg of process.argv.slice(2)) {
        if (arg.startsWith("port")) {
            kms_config.service.port = arg.split("=")[1]
        } else if (arg.startsWith("run_mode")) {
            kms_config.service.run_mode = arg.split("=")[1]
        } else if (arg.startsWith("database_username")) {
            kms_config.database.username = arg.split("=")[1]
        } else if (arg.startsWith("database_password")) {
            kms_config.database.password = arg.split("=")[1]
        } else if (arg.startsWith("database_server")) {
            kms_config.database.server = arg.split("=")[1]
        } else if (arg.startsWith("database_port")) {
            kms_config.database.port = arg.split("=")[1]
        } else if (arg.startsWith("database_db")) {
            kms_config.database.db = arg.split("=")[1]
        }
    }

    // check config
    let ERR_MSG_PREFIX = "Exception :: service Initialize exception! "
    if (!kms_config.database.username ||
        !kms_config.database.password ||
        !kms_config.database.server ||
        !kms_config.database.port ||
        !kms_config.database.db) {
        logger.error(ERR_MSG_PREFIX, '[ERR_DATABSE_BAD_SET]: couchdb url error')
        process.exit(0)
    }
    if (!/^\d+$/.test(kms_config.service.port) || kms_config.service.port < 0 || kms_config.service.port > 65536) {
        logger.error(ERR_MSG_PREFIX, '[ERR_DATABSE_BAD_SET]: port should be >= 0 and < 65536. Received .')
        process.exit(0)
    }
    if (!kms_config.service.run_mode) {
        logger.error(ERR_MSG_PREFIX, '[ERR_DATABSE_BAD_SET]: run_mode cannot be empty.')
        process.exit(0)
    }
}

module.exports = {
    load_kms_config,
    kms_config,
    Definition,
    ehsm_keySpec_t,
    ehsm_keyorigin_t,
    ehsm_action_t,
    ehsm_digest_mode_t,
    ehsm_message_type_t,
    ehsm_keyusage_t,
    ehsm_padding_mode_t,
}
