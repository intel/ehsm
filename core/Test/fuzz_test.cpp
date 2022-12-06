#include "fuzz_test.h"
#include "json_utils.h"
#include "base64.h"

#include <cstring>
#include <assert.h>

void test_demo(uint8_t *plaintext, size_t plaintext_len, uint8_t *aad, size_t aad_len)
{
    uint32_t keyspec = EH_AES_GCM_128;

    char *returnJsonChar = nullptr;

    char *cmk_base64 = nullptr;
    char *ciphertext_base64 = nullptr;
    char *plaintext_base64 = nullptr;
    std::string input_plaintext_base64 = base64_encode((const uint8_t *)plaintext, plaintext_len);
    std::string input_aad_base64 = base64_encode((const uint8_t *)aad, aad_len);

    RetJsonObj retJsonObj;
    JsonObj param_json;
    JsonObj payload_json;
    payload_json.addData_uint32("keyspec", keyspec);
    payload_json.addData_uint32("origin", EH_INTERNAL_KEY);
    param_json.addData_uint32("action", EH_CREATE_KEY);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    assert(retJsonObj.getCode() == 200);
    
    cmk_base64 = retJsonObj.readData_cstr("cmk");

    payload_json.clear();
    payload_json.addData_string("cmk", cmk_base64);
    payload_json.addData_string("plaintext", input_plaintext_base64);
    payload_json.addData_string("aad", input_aad_base64);

    param_json.addData_uint32("action", EH_ENCRYPT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    assert(retJsonObj.getCode() == 200);

    ciphertext_base64 = retJsonObj.readData_cstr("ciphertext");
    payload_json.addData_string("ciphertext", ciphertext_base64);

    param_json.addData_uint32("action", EH_DECRYPT);
    param_json.addData_JsonValue("payload", payload_json.getJson());

    returnJsonChar = EHSM_FFI_CALL((param_json.toString()).c_str());
    retJsonObj.parse(returnJsonChar);

    assert(retJsonObj.getCode() == 200);
    plaintext_base64 = retJsonObj.readData_cstr("plaintext");
    
    assert(plaintext_base64 == input_plaintext_base64);

    SAFE_FREE(plaintext_base64);
    SAFE_FREE(ciphertext_base64);
    SAFE_FREE(cmk_base64);
    SAFE_FREE(returnJsonChar);
}