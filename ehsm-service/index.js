const express = require('express')
const ffi = require('ffi-napi');
const app = express();
// app.use(express.urlencoded());
app.use(express.json());
const logger = require('./logs/logger');

const pramas = require('./constans.js')
const port = 3000;

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
 * 校验sign
 */
const _checkSign = function (req,res,next){
  const _logData = {
    body:req.body,
    query:req.query
  }
  logger.info(JSON.stringify(_logData));
  const {appid,nonce,timestamp,sign, payload} = req.body;
  if(!appid || !nonce|| !timestamp  || !sign || !payload) {
    res.send(result(401,'缺少必要参数'));
    return;
  }
  // todo sign 校验
  next();
}
/**
 * 校验payload
 */
 const _checkPayload = function (req,res,next){
   const action = req.query.Action;
  const { payload } = req.body;
  const currentPayLoad = pramas[action];
  for (const key in currentPayLoad) {
    if(payload[key] == undefined) {
      res.send(result(401,'payload参数不全'));
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
 * sign 拦截
 */

 app.use(_checkSign);
/**
 * payload 拦截
 */
 app.use(_checkPayload);

/**
 * 
 * @param {*} str 
 * @returns base64Str
 */
const stringToBase64 = (str) => Buffer.from(str).toString('base64');
/**
 * 
 * @param {*} base64Str 
 * @returns string
 */
const base64ToString = (base64Str) => Buffer.from(base64Str,'base64').toString();


// curl -i -k  -H "Content-type: application/json" -X POST  -d '{"appid":"t123","nonce":"t123","timestamp":"t123","sign":"t123","payload":{"mechanism":0.1,"origin":0.1}}' http://10.239.127.69:3009/ehsm?Action=CreateKey


app.post('/ehsm', function (req, res) {

  const payload = req.body.payload;
  switch (req.query.Action) {
    case apis.CreateKey:
      const {mechanism, origin} = payload;
      const mechanismType = {
        "EHM_AES_GCM_128": 0x00000000,
        "EHM_SM4": 0x00000001,
        "EHM_RSA_3072": 0x00000002,
      };
      const originType = {
        "EHO_INTERNAL_KEY": 0,
        "EHO_EXTERNAL_KEY": 1
      }
      
      const intMechanism = mechanismType[mechanism];
	    const intOrigin = originType[origin];
      console.log(`转换后的入参,mechanism: ${intMechanism},origin: ${intOrigin}`)
      //const o64 = stringToBase64(origin)
      const ehsm = ffi.Library('./libehsmnapi',{'CreateKey_napi':['string',['int','int']]});
      
     const r = ehsm.CreateKey_napi(intMechanism, intOrigin)

     console.log(`出参：${r}`)
     res.send(r);
      break;
    case apis.Encrypt:
      // todo
      break;
    case apis.Decrypt:
      // todo
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

