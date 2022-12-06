const ffi = require('ffi-napi')
const {
    Definition
} = require('./constant')

const ehsm_ffi = ffi.Library('./libehsmprovider', {
    /**
        EHSM_FFI_CALL 
        Description:
            call napi function

        First String ==> params Json: 
            {
                action: string [CreateKey, Encrypt, Decrypt, Sign, Verify...]
                payload: {
                    [additional parameter]
                }
            }
        
        Second String ==> out json:
            {
                code: int,
                message: string,
                result: {
                  xxx : xxx
                }
            }
    */
    EHSM_FFI_CALL: ['int', ['string', 'string']]
})


const ehsm_napi = (jsonParam) => {
    let outBuffer = new Buffer.alloc(Definition.FFI_BUFFER_SIZE);
    ehsm_ffi.EHSM_FFI_CALL(jsonParam, outBuffer)
    let jsonStr = outBuffer.toString()
    jsonStr = jsonStr.substring(0, jsonStr.lastIndexOf('}') + 1);
    return JSON.parse(jsonStr);
}

module.exports = ehsm_napi
