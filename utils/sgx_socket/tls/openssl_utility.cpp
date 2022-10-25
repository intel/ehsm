/**
*
* MIT License
*
* Copyright (c) Open Enclave SDK contributors.
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE
*
*/

#include "openssl_utility.h"

sgx_status_t generate_certificate_and_pkey(X509*& certificate, EVP_PKEY*& pkey)
{
    quote3_error_t qresult = SGX_QL_SUCCESS;
    sgx_status_t result = SGX_ERROR_UNEXPECTED;
    uint8_t* output_certificate = NULL;
    size_t output_certificate_size = 0;
    uint8_t* private_key_buffer = nullptr;
    size_t private_key_buffer_size = 0;
    uint8_t* public_key_buffer = nullptr;
    size_t public_key_buffer_size = 0;
    const unsigned char* certificate_buffer_ptr = nullptr;
    BIO* mem = nullptr;
    int key_type = RSA_TYPE;

    if (key_type) {
        log_d(" generating keys by EC P-384\n");
    }
    else
    {
        log_d(" generating keys by RSA 3072\n");
    }
    result = generate_key_pair(
        key_type, &public_key_buffer,
        &public_key_buffer_size,
        &private_key_buffer,
        &private_key_buffer_size);
    if (result != SGX_SUCCESS)
    {
        log_d(" failed to generate RSA key pair\n");
        goto done;
    }

    /* log_d("public_key_buf_size:[%ld]\n", public_key_buffer_size);
    log_d("%s\n", public_key_buffer);
	log_d("private_key_buf_size:[%ld]\n", private_key_buffer_size);
	log_d("%s\n", private_key_buffer); */
    qresult = tee_get_certificate_with_evidence(
        certificate_subject_name,
        private_key_buffer,
        private_key_buffer_size,
        public_key_buffer,
        public_key_buffer_size,
        &output_certificate,
        &output_certificate_size);

    if (qresult != SGX_QL_SUCCESS || output_certificate == nullptr)
    {
        if (output_certificate == nullptr)
            log_d(" null certificate\n");
        p_sgx_tls_qe_err_msg(qresult);
        goto done;
    }

    // temporary buffer required as if d2i_x509 call is successful
    // certificate_buffer_ptr is incremented to the byte following the parsed
    // data. sending certificate_buffer_ptr as argument will keep
    // output_certificate pointer undisturbed.

    certificate_buffer_ptr = output_certificate;

    if ((certificate = d2i_X509(
             nullptr,
             &certificate_buffer_ptr,
             (long)output_certificate_size)) == nullptr)
    {
        log_d("Failed to convert DER format certificate to X509 structure\n");
        goto done;
    }
    mem = BIO_new_mem_buf((void*)private_key_buffer, -1);
    if (!mem)
    {
        log_d("Failed to convert private key buf into BIO_mem\n");
        goto done;
    }
    if ((pkey = PEM_read_bio_PrivateKey(mem, nullptr, 0, nullptr)) == nullptr)
    {
        log_d("Failed to convert private key buffer into EVP_KEY format\n");
        goto done;
    }

    result = SGX_SUCCESS;
done:
    if (private_key_buffer)
        free(private_key_buffer);
    if (public_key_buffer)
        free(public_key_buffer);
    certificate_buffer_ptr = nullptr;

    if (mem)
        BIO_free(mem);
    if (output_certificate)
        tee_free_certificate(output_certificate);
    return result;
}

sgx_status_t load_tls_certificates_and_keys(
    SSL_CTX* ctx,
    X509*& certificate,
    EVP_PKEY*& pkey)
{
    sgx_status_t result = SGX_ERROR_UNEXPECTED;

    if (generate_certificate_and_pkey(certificate, pkey) != SGX_SUCCESS)
    {
        log_d("Cannot generate certificate and pkey\n");
        goto exit;
    }

    if (certificate == nullptr)
    {
        log_d("null cert\n");
        goto exit;
    }

    if (!SSL_CTX_use_certificate(ctx, certificate))
    {
        log_d("Cannot load certificate on the server\n");
        goto exit;
    }

    if (!SSL_CTX_use_PrivateKey(ctx, pkey))
    {
        log_d("Cannot load private key on the server\n");
        goto exit;
    }

    /* verify private key */
    if (!SSL_CTX_check_private_key(ctx))
    {
        log_d("Private key does not match the public certificate\n");
        goto exit;
    }
    result = SGX_SUCCESS;
exit:
    return result;
}

sgx_status_t initalize_ssl_context(SSL_CONF_CTX*& ssl_conf_ctx, SSL_CTX*& ctx)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // Configure the SSL context based on Open Enclave's security guidance.
    const char* cipher_list_tlsv12_below =
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-"
        "AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-"
        "AES256-SHA384:"
        "ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384";
    const char* cipher_list_tlsv13 =
        "TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256";
    const char* supported_curves = "P-521:P-384";

    SSL_CONF_CTX_set_ssl_ctx(ssl_conf_ctx, ctx);
    SSL_CONF_CTX_set_flags(
        ssl_conf_ctx,
        SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_SERVER | SSL_CONF_FLAG_CLIENT);
    int ssl_conf_return_value = -1;
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "MinProtocol", "TLSv1.2")) < 0)
    {
        log_d(
            "Setting MinProtocol for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "MaxProtocol", "TLSv1.3")) < 0)
    {
        log_d(
            "Setting MaxProtocol for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value = SSL_CONF_cmd(
             ssl_conf_ctx, "CipherString", cipher_list_tlsv12_below)) < 0)
    {
        log_d(
            "Setting CipherString for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value = SSL_CONF_cmd(
             ssl_conf_ctx, "Ciphersuites", cipher_list_tlsv13)) < 0)
    {
        log_d(
            "Setting Ciphersuites for ssl context configuration failed with "
            "error %d \n",
            ssl_conf_return_value);
        goto exit;
    }
    if ((ssl_conf_return_value =
             SSL_CONF_cmd(ssl_conf_ctx, "Curves", supported_curves)) < 0)
    {
        log_d(
            "Setting Curves for ssl context configuration failed with error %d "
            "\n",
            ssl_conf_return_value);
        goto exit;
    }
    if (!SSL_CONF_CTX_finish(ssl_conf_ctx))
    {
        log_d("Error finishing ssl context configuration \n");
        goto exit;
    }
    ret = SGX_SUCCESS;
exit:
    return ret;
}


int read_from_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int ret = -1;
    unsigned char buffer[200]; // the expected payload to be read from peer is
                               // at maximum of size 200
    int bytes_read = 0;
    do
    {
        unsigned int len = sizeof(buffer) - 1;
        memset(buffer, 0, sizeof(buffer));
        bytes_read = SSL_read(ssl_session, buffer, (size_t)len);

        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            log_d("Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            break;
        }

        log_d(" %d bytes read from session peer\n", bytes_read);
        size_t sbyte_read = bytes_read;
        // check to see if received payload is expected
        if ((sbyte_read != payload_length) ||
            (memcmp(payload, buffer, bytes_read) != 0))
        {
            log_d(
                "ERROR: expected reading %lu bytes but only "
                "received %d bytes\n",
                payload_length,
                bytes_read);
            ret = bytes_read;
            goto exit;
        }
        else
        {
            log_i(" received all the expected data from the session peer\n\n");
            ret = 0;
            break;
        }
    } while (1);

exit:
    return ret;
}

int write_to_session_peer(
    SSL*& ssl_session,
    const uint8_t* payload,
    size_t payload_length)
{
    int bytes_written = 0;
    int ret = 0;

    while ((bytes_written = SSL_write(ssl_session, payload, payload_length)) <=
           0)
    {
        int error = SSL_get_error(ssl_session, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        log_d("Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto exit;
    }

    log_d("%lu bytes written to session peer\n\n", payload_length);
exit:
    return ret;
}
