const express = require('express')
const crypto = require('crypto')
const app = express();
const logger = require('./logs/logger');
const ehsm_napi = require('./ehsm_napi');
const { ehsm_kms_params, ehsm_keyspec_t, ehsm_keyorigin_t} = require('./ehsm_kms_params.js')
const userInfo = require('./user_info')
app.use(express.json());

const PORT = process.argv.slice(2)[0] || 9000;

const MAX_TIME_STAMP_DIFF = 10 * 60 * 1000;
const NONCE_CACHE_TIME = MAX_TIME_STAMP_DIFF * 2 ;
const TIMESTAMP_LEN = 13;


const result = (code, msg, data={}) => {
  return {
    code: code,
    message: msg,
    result: {
      ...data
    }
  }
}

const apis= {
  CreateKey: 'CreateKey',
  Encrypt: 'Encrypt',
  Decrypt: 'Decrypt',
  GenerateDataKey: 'GenerateDataKey',
  GenerateDataKeyWithoutPlaintext: 'GenerateDataKeyWithoutPlaintext',
  ExportDataKey: 'ExportDataKey',
  Sign: 'Sign',
  Verify: 'Verify',
  AsymmetricEncrypt: 'AsymmetricEncrypt',
  AsymmetricDecrypt: 'AsymmetricDecrypt'
}

// base64 encode
const base64_encode = (str) => new Buffer.from(str).toString('base64');
// base64 decode
const base64_decode =(base64_str) =>new Buffer.from(base64_str, 'base64').toString();

/**
 * The parameters of non empty parameter values in set sign_parmas are sorted from small
 * to large according to the ASCII code of the parameter name (dictionary order),
 * and the format of URL key value pairs (i.e. key1 = value1 & key2 = Value2...)
 * is spliced into a string
 * @param {object} sign_parmas
 * @returns string
 */
const params_sort_str = (sign_parmas) => {
  let str = '';
  try {
    const sort_params_key_arr = Object.keys(sign_parmas).sort()
    for(var k of sort_params_key_arr) {
      if(sign_parmas[k] != '' && sign_parmas[k] != undefined && sign_parmas[k] != null) {
        str += (str&& ('&' + '')) + k + '=' + (typeof sign_parmas[k] == 'object' ? params_sort_str(sign_parmas[k]) : sign_parmas[k])
      }
    }
    return str;
  } catch (error) {
    res.send(result(404, 'Not Fount', {}));
    logger.info(JSON.stringify(error));
    return str;
  }
}

/**
 * Verify each parameter in the payload, such as data type, 
 * data length, whether it is the specified value,
 * whether it is required, etc.
 * For parameter description, see <ehsm_kms_params.js>
 * @param {object} req
 * @param {object} res
 * @returns true | false
 */
 const _checkPayload = function (req, res){
  try {
    const action = req.query.Action;
    const { payload } = req.body;
    const currentPayLoad = ehsm_kms_params[action];
    for (const key in currentPayLoad) {
      if ((payload[key] == undefined || payload[key] == '' || !payload[key]) && currentPayLoad[key].required) {
        res.send(result(400, 'Missing required parameters'));
        return false;
      }
      if(currentPayLoad[key].type == 'string' && payload[key]) {
        if(typeof payload[key] != 'string'){
          res.send(result(400, `${key} must be of string type`));
          return false;
        }
        if(payload[key] != undefined && (
          (currentPayLoad[key].maxLength && payload[key].length > currentPayLoad[key].maxLength) ||
          (currentPayLoad[key].minLength && payload[key].length < currentPayLoad[key].minLength)
        )) {
          res.send(result(400, `${key} length error`));
          return false;
        }
      }
      if(currentPayLoad[key].type == 'int' && payload[key]) {
        if(!Number.isInteger(payload[key])){
          res.send(result(400, `${key} must be of integer type`));
          return false;
        }
        if(payload[key] != undefined && (
          (currentPayLoad[key].maxNum && payload[key] > currentPayLoad[key].maxNum) ||
          (currentPayLoad[key].minNum && payload[key] < currentPayLoad[key].minNum)
        )) {
          res.send(result(400, `${key} must be between ${currentPayLoad[key].minNum} and ${currentPayLoad[key].maxNum}`));
          return false;
        }
      }
      if(currentPayLoad[key].type == 'const' && payload[key]) {
        if(!currentPayLoad[key].arr.includes(payload[key])){
          res.send(result(400, currentPayLoad[key].errortext || `${key} error`));
          return false;
        }
      }
    }
    return true;
  } catch (error) {
    res.send(result(400, 'Parameter exception', {}));
    logger.info(JSON.stringify(error));
    return false;
  }
}

// Clear nonce cache for more than 15 minutes
const nonce_database = {};
const nonce_cache_timer = setInterval(() => {
  try {
    for (const appid in nonce_database) {
      let slice_index = nonce_database[appid] && nonce_database[appid].findIndex((nonce_data) => {
        return (new Date().getTime() - nonce_data.nonce_timestamp) > NONCE_CACHE_TIME;
      });
      if(slice_index > 0) {
        nonce_database[appid] = nonce_database[appid].slice(slice_index);
      }
      if(slice_index == 0) {
        delete nonce_database[appid];
      }
    }
  } catch (error) {
    res.send(result(404, 'Not Fount', {}));
    logger.info(JSON.stringify(error));
  }
}, NONCE_CACHE_TIME / 2);

/**
 * The calibration time error is within <MAX_TIME_STAMP_DIFF> minutes
 * @param {string} timestamp 
 * @returns true | false
 */
const _checkTimestamp = (timestamp) => {
  return Math.abs(new Date().getTime() - timestamp) < MAX_TIME_STAMP_DIFF
}

/**
 * check params
 */
const _checkParams = function (req,res,next){
  try {
    let ip = req.ip;
    if (ip.substr(0, 7) == "::ffff:") {
      ip = ip.substr(7)
    }
    const _logData = {
      body: req.body,
      query: req.query,
      ip,
    }
    logger.info(JSON.stringify(_logData));

    const {appid, timestamp: nonce, timestamp, sign, payload} = req.body;
    if(!appid || !nonce|| !timestamp || !sign || !payload) {
      res.send(result(400,'Missing required parameters'));
      return;
    }
    if(typeof appid != 'string' 
      || typeof nonce != 'string' 
      || typeof timestamp != 'string' 
      || typeof payload != 'object' 
      || typeof sign != 'string') {
      res.send(result(400,'param type error'));
      return;
    }
    if(!userInfo[appid]) {
      res.send(result(400, 'Appid not found'));
      return;
    }
    if(timestamp.length != TIMESTAMP_LEN) {
      res.send(result(400, 'Timestamp length error'));
      return;
    }
    if(!_checkTimestamp(timestamp)) {
      res.send(result(400, 'Timestamp error'));
      return;
    }
   
    const nonce_data ={ nonce, nonce_timestamp: new Date().getTime() }
    if(!nonce_database[appid]) {
      nonce_database[appid] = [nonce_data];
    } else if(!!nonce_database[appid] && nonce_database[appid].findIndex(nonce_data => nonce_data.nonce == nonce) > -1) {
      res.send(result(400, "Timestamp can't be repeated in 20 minutes"));
      return;
    } else {
      nonce_database[appid].unshift(nonce_data);
    }
    // check payload
    const _checkPayload_res = _checkPayload(req, res, next);
    if(!_checkPayload_res){
      return;
    };
    
    // check sign
    let appkey = userInfo[appid];
    let sign_parmas = { appid, timestamp, payload }
    let sign_string = params_sort_str(sign_parmas);
    let local_sign = crypto.createHmac('sha256', appkey).update(sign_string, 'utf8').digest('base64');
    if(sign != local_sign) {
      res.send(result(400,'sign error'));
      return;
    }
    next();
  } catch (error) {
    res.send(result(404, 'Not Fount', {}));
    logger.info(JSON.stringify(error));
  }
}

app.use(_checkParams);

const NAPI_Initialize = ehsm_napi.NAPI_Initialize();
if(JSON.parse(NAPI_Initialize)['code'] != 200) {
  console.log('service Initialize exception!')
  clearInterval(nonce_cache_timer);
	process.exit(0);
}

/**
 * ehsm napi result
 * @param {function name} action 
 * @param {} res 
 * @param {NAPI_* function params} params 
 * @returns 
 */

const napi_result = (action, res, params) => {
  try {
    // r : NAPI_(*) Return results
    const r = JSON.parse(ehsm_napi[`NAPI_${action}`](...params));
    res.send(r);
  } catch (e) {
    res.send(result(400, 'Parsing error'))
  }
}

/**
 * router
 */
app.post('/ehsm', function (req, res) {
  try {
    const PAYLOAD = req.body.payload;
    
    // ACTION: request function name
    const ACTION = req.query.Action;
    
    if(ACTION === apis.CreateKey) {
    /**
     * CreateKey
     */
      let { keyspec, origin } = PAYLOAD;
      keyspec = ehsm_keyspec_t[keyspec];
      origin = ehsm_keyorigin_t[origin]
      napi_result(ACTION ,res, [keyspec, origin]);
    } else if(ACTION === apis.Encrypt) {
    /**
     * Encrypt
     */
      const { cmk_base64, plaintext, aad= '' } = PAYLOAD;
      napi_result(ACTION ,res, [cmk_base64, plaintext, aad]);
    } else if(ACTION === apis.Decrypt) {
    /**
     * Decrypt
     */
      const { cmk_base64, ciphertext, aad= '' } = PAYLOAD;
      napi_result(ACTION ,res, [cmk_base64, ciphertext, aad]);
    } else if(ACTION === apis.GenerateDataKey) {
    /**
     * GenerateDataKey
     */
      const { cmk_base64, keylen, aad= '' } = PAYLOAD;
      napi_result(ACTION ,res, [cmk_base64, keylen, aad]);
    } else if(ACTION === apis.GenerateDataKeyWithoutPlaintext) {
    /**
     * GenerateDataKeyWithoutPlaintext
     */
      const { cmk_base64, keylen, aad= '' } = PAYLOAD;
      napi_result(ACTION ,res, [cmk_base64, keylen, aad]);
    } else if(ACTION === apis.Sign) {
    /**
     * Sign
     */
      const { cmk_base64, digest } = PAYLOAD;
      napi_result(ACTION ,res, [cmk_base64, digest]);
    } else if(ACTION === apis.Verify) {
    /**
     * Verify
     */
      const { cmk_base64, digest, signature_base64 } = PAYLOAD;
      napi_result(ACTION ,res, [cmk_base64, digest, signature_base64]);
    } else if(ACTION === apis.AsymmetricEncrypt) {
    /**
     * AsymmetricEncrypt
     */
      const { cmk_base64, plaintext } = PAYLOAD;
      napi_result(ACTION ,res, [cmk_base64, plaintext]);
    } else if(ACTION === apis.AsymmetricDecrypt) {
    /**
     * AsymmetricDecrypt
     */
      const { cmk_base64, ciphertext_base64 } = PAYLOAD;
      napi_result(ACTION ,res, [cmk_base64, ciphertext_base64]);
    } else if(ACTION === apis.ExportDataKey) {
    /**
     * ExportDataKey
     */
      const { cmk_base64, ukey_base64, aad= '', olddatakey_base } = PAYLOAD;
      napi_result(ACTION ,res, [cmk_base64, ukey_base64, aad, olddatakey_base]);
    } else {
      res.send(result(404, 'Not Fount', {}));
    }
  } catch (error) {
    res.send(result(404, 'Not Fount', {}));
    logger.info(JSON.stringify(error));
  }
  
})
process.on('SIGINT', function() {
  console.log('ehsm kms service exit')
  ehsm_napi.NAPI_Finalize();
  clearInterval(nonce_cache_timer);
	process.exit(0);
});

const  getIPAdress = () => {
  try {
    var interfaces = require('os').networkInterfaces();
    for (var devName in interfaces) {
      var iface = interfaces[devName];
      for (var i = 0; i < iface.length; i++) {
          var alias = iface[i];
          if (alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal) {
              return alias.address;
          }
      }
    }
  } catch (error) {
    logger.info(JSON.stringify(error));
    res.send(result(404, 'Not Fount', {}));
  }
}

app.listen(PORT, () => {
  console.log(`ehsm_ksm_service application listening at ${getIPAdress()}:${PORT}`)
})

