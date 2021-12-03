const express = require('express')
const ffi = require('ffi-napi');
const app = express();
const logger = require('./logs/logger');
const napiparams = require('./napiparams.js')

app.use(express.json());

const port = 3000;

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
}

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
  // todo sign 
  next();
}
/**
 * check payload
 */
 const _checkPayload = function (req,res,next){
   const action = req.query.Action;
  const { payload } = req.body;
  const currentPayLoad = napiparams[action];
  for (const key in currentPayLoad) {
    if (payload[key] == undefined) {
      res.send(result(400, 'The payload parameter is incomplete'));
      return;
    }
    
    // const p = currentPayLoad[key];
    // for (const checkType in p) {
    //   switch (checkType) {
    //     case 'type':
          
    //       break;
    //     case 'maxLength':
        
    //       break;
    //     case 'length':
        
    //       break;
    //     default:
    //       break;
    //   }
    // }
    // if()
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
/**
 * parameter mechanism type
 */
const mechanismType = {
  "EHM_AES_GCM_128": 0,
  "EHM_SM4": 1,
  "EHM_RSA_3072": 2,
};
/**
 * ehsm_napi function object
 */ 
const ehsm_napi = ffi.Library('./libehsmnapi',{
  'CreateKey_napi': ['string',['int','int']],
  'Encrypt_napi': ['string',['int','string', 'string']],
  'Decrypt_napi': ['string',['int','string', 'string']],
  'GenerateDataKey_napi': ['string',['int','string']],
});
const napi_result = (action, res, params) => {
  try {
    res.send(ehsm_napi[`${action}_napi`](...params));
  } catch (e) {
    res.send(e)
  }
  return;
}
app.post('/ehsm', function (req, res) {
  const PAYLOAD = req.body.payload;
  const ACTION = req.query.Action;
  const intMechanism = mechanismType[PAYLOAD.mechanism];
  if(ACTION === apis.CreateKey) {
    const originType = {
      "EHO_INTERNAL_KEY": 0,
      "EHO_EXTERNAL_KEY": 1
    };
    const { origin } = PAYLOAD;
    napi_result(ACTION ,res, [intMechanism, originType[origin]]);
  } else if(ACTION === apis.Encrypt) {
    const { data, key } = PAYLOAD;
    napi_result(ACTION ,res, [intMechanism, key, data]);
  } else if(ACTION === apis.Decrypt) {
    const { enData, key } = PAYLOAD;
    napi_result(ACTION ,res, [intMechanism, key, enData]);
  } else if(ACTION === apis.GenerateDataKey) {
    const { masterKey } = PAYLOAD;
    napi_result(ACTION ,res, [intMechanism, masterKey]);
  } else {
    res.send(result(404, 'fail', {}));
  }
})

app.listen(port, () => {
    console.log(`Example application listening at http://localhost:${port}`)
})

