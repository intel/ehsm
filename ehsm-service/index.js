const express = require('express')
const ffi = require('ffi-napi');
const app = express();
// app.use(express.urlencoded());
app.use(express.json());
const logger = require('./logs/logger');

const pramas = require('./constans.js')
const port = 10000;

const result = (code, msg, data) => {
  return {
    code: code,
    message: msg,
    result: {
      data
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
    body:req.body,
    query:req.query
  }
  logger.info(JSON.stringify(_logData));
  const {appid,nonce,timestamp,sign, payload} = req.body;
  if(!appid || !nonce|| !timestamp  || !sign || !payload) {
    res.send(result(401,'Missing required parameters'));
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
  const currentPayLoad = pramas[action];
  for (const key in currentPayLoad) {
    if(payload[key] == undefined) {
      res.send(result(401,'The payload parameter is incomplete'));
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

app.post('/ehsm', function (req, res) {
  const payload = req.body.payload;
  const {mechanism, origin, data, enData, key} = payload;
  const mechanismType = {
    "EHM_AES_GCM_128": 0x00000000,
    "EHM_SM4": 0x00000001,
    "EHM_RSA_3072": 0x00000002,
  };
  const originType = {
    "EHO_INTERNAL_KEY": 0,
    "EHO_EXTERNAL_KEY": 1
  };
  const intMechanism = mechanismType[mechanism];
  const intOrigin = originType[origin];

  switch (req.query.Action) {
    case apis.CreateKey:      
      let CreateKey_napi = ffi.Library('./libehsmnapi',{'CreateKey_napi':['string',['int','int']]});      
      const CreateKey_r = CreateKey_napi.CreateKey_napi(intMechanism, intOrigin);
      res.send(CreateKey_r);
      break;
    case apis.Encrypt:     
      const Encrypt_napi = ffi.Library('./libehsmnapi',{'Encrypt_napi':['string',['int','string', 'string']]});
      const encrypt_r = Encrypt_napi.Encrypt_napi(intMechanism,key, data);
      res.send(encrypt_r);
      break;
    case apis.Decrypt:
      const Decrypt_napi = ffi.Library('./libehsmnapi',{'Decrypt_napi':['string',['int','string', 'string']]});
      const decrypt_r = Decrypt_napi.Decrypt_napi(intMechanism,key, enData)
      res.send(decrypt_r);
      break;
    case apis.GenerateDataKey:
      // todo
      break;
    case apis.GenerateDataKeyWithoutPlaintext:
      // todo
      break;
    case apis.ExportDataKey:
      // todo
      break; 
    case apis.Sign:
      // todo
      break;
    case apis.Verify:
      // todo
      break;
    default:
      break;
  }

  // let _mockRes = result(200, 'success', {key: 'the text after CreateKey'})
  // res.send(_mockRes)
})

app.listen(port, () => {
    console.log(`Example application listening at http://localhost:${port}`)
})

