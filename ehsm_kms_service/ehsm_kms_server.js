const express = require('express')
const crypto = require('crypto')
const app = express();
const logger = require('./logs/logger');
const ehsm_napi = require('./ehsm_napi');
const { ehsm_kms_params, ehsm_keyspec_t, ehsm_keyorigin_t} = require('./ehsm_kms_params.js')

app.use(express.json());

const port = 9000;

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
 * check sign
 */
const _checkSign = function (req,res,next){
  const _logData = {
    body: req.body,
    query: req.query
  }
  logger.info(JSON.stringify(_logData));
  const {appid,nonce,timestamp,sign, payload} = req.body;
  if(!appid || !nonce|| !timestamp  || !sign || !payload) {
    res.send(result(400,'Missing required parameters'));
    return;
  }
  let test_app_key = '202112345678';

  let str = '';
  let sign_parmas = {appid, nonce, timestamp} 
  for(var k in sign_parmas){
    if(!str) {
      str += k + '=' + sign_parmas[k]
    } else{
      str += '&' + k + '=' + sign_parmas[k]
    }
  }
  str += '&app_key=' + test_app_key;
  let local_sign = crypto.createHmac('sha256',test_app_key).update(str, 'utf8').digest('base64');
  if(sign != local_sign) {
    res.send(result(400,'sign error'));
    return;
  }

  next();
}
/**
 * check payload
 */
const _checkPayload = function (req,res,next){
  const action = req.query.Action;
  const { payload } = req.body;
  const currentPayLoad = ehsm_kms_params[action];
  for (const key in currentPayLoad) {
    if (payload[key] == undefined) {
      res.send(result(400, 'The payload parameter is incomplete'));
      return;
    }
  }
  next();
}
/**
 * sign 
 */

app.use(_checkSign);
/**
 * payload 
 */
app.use(_checkPayload);

const NAPI_Initialize = ehsm_napi.NAPI_Initialize();

if(JSON.parse(NAPI_Initialize)['code'] != 200) {
  console.log('service Initialize exception!')
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
    res.send(result(400, e))
  }
  return;
}

/**
 * router
 */
app.post('/ehsm', function (req, res) {
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
    const { cmk_base64, plaintext, aad } = PAYLOAD;
    napi_result(ACTION ,res, [cmk_base64, plaintext, aad]);
  } else if(ACTION === apis.Decrypt) {
  /**
   * Decrypt
   */
    const { cmk_base64, ciphertext, aad } = PAYLOAD;
    napi_result(ACTION ,res, [cmk_base64, ciphertext, aad]);
  } else if(ACTION === apis.GenerateDataKey) {
  /**
   * GenerateDataKey
   */
    const { cmk_base64, keylen, aad } = PAYLOAD;
    napi_result(ACTION ,res, [cmk_base64, keylen, aad]);
  } else if(ACTION === apis.GenerateDataKeyWithoutPlaintext) {
  /**
   * GenerateDataKeyWithoutPlaintext
   */
    const { cmk_base64, keylen, aad } = PAYLOAD;
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
  } else {
    res.send(result(404, 'Not Fount', {}));
  }
})
process.on('SIGINT', function() {
  console.log('ehsm kms service exit')
  ehsm_napi.NAPI_Finalize();
	process.exit(0);
});

const  getIPAdress = () => {
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
}

app.listen(port, () => {
  console.log(`ehsm_ksm_service application listening at ${getIPAdress()}:${port}`)
})

