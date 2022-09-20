const ffi = require('ffi-napi')

const ehsm_napi = ffi.Library('./libehsmnapi', {
  /**
    EHSM_FFI_CALL 
    Description:
      call napi function

    params Json: 
      {
          action: string [CreateKey, Encrypt, Decrypt, Sign, Verify...]
          payload: {
              [additional parameter]
          }
      }
    
    return json
      {
        code: int,
        message: string,
        result: {
          xxx : xxx
        }
      }
  */
  EHSM_FFI_CALL: ['string', ['string']]
})

module.exports = ehsm_napi
