# Client SDK interface for Rust

It will provide the following interfaces:

---

**Key Management APIs:**

- create_key
- encrypt
- decrypt
- sign
- verify
- asymmetric_encrypt
- asymmetric_decrypt
- generate_datakey
- generate_datakey_without_plaintext
- export_datakey
- get_publickey
- get_version
- enroll
- list_key
- delete_key
- delete_allkey
- enable_key
- disable_key

---

**Secret Management APIs:**

- create_secret
- update_secret_desc
- put_secret_value
- list_secret_version_ids
- list_secrets
- describe_secret
- delete_secret
- get_secret_value
- restore_secret

## Start eHSM-KMS service

Notes: it need to run on a sgx capable machine.

```shell
# start ehsm-kms on a single machine without remote attestation
./run_with_single.sh
```

or you can build and run ehsm-kms with Docker Compose:

```shell
# Download the ehsm code from github
git clone --recursive https://github.com/intel/ehsm.git ehsm && cd ehsm
vim docker/.env

# Modify the docker/.env configurations
HOST_IP=1.2.3.4               # MUST modify it to your host IP.
PCCS_URL=https://1.2.3.4:8081 # MUST modify it to your pccs server url.
DKEYSERVER_PORT=8888          # (Optional) the default port of dkeyserver, modify it if you want.
KMS_PORT=9000                 # (Optional) the default KMS port, modify it if you want.
TAG_VERSION=main              # (Optional) the default code base is using the main latest branch, modify it to specific tag if you want.

# start to build and run the docker images (couchdb, dkeyserver, dkeycache, ehsm_kms_service)
cd docker && docker compose up -d
```

## Run the unit-test

Notes: this can be run on non-sgx capable machine.

### Enroll to eHSM-KMS with Restful interface

```shell
curl -v -k -G "https://<kms_ip>:<port>/ehsm?Action=Enroll"

{"code":200,"message":"successful","result":{"apikey":"xbtXGHwBexb1pgnEz8JZWHLgaSVb1xSk","appid":"56c46c76-60e0-4722-a6ad-408cdd0c62c2"}}
```

### Export eHSM information to environment variables

```shell
export EHSM_APPID=56c46c76-60e0-4722-a6ad-408cdd0c62c2
export EHSM_APIKEY=xbtXGHwBexb1pgnEz8JZWHLgaSVb1xSk
export EHSM_ADDR=https://<kms_ip>:<port>
```

### Run test

```shell
#cargo test

cargo test

   Compiling ehsm_client v0.1.0 (/home/ehsm/lst/my_work/ehsm/sdk/rust)
    Finished test [unoptimized + debuginfo] target(s) in 3.54s
     Running unittests src/lib.rs (target/debug/deps/ehsm_client-0800361bec00eb7d)

running 11 tests
test test::tests::test_generate_key_err ... ok
test test::tests::test_get_publickey ... ok
test test::tests::test_sm2_sign_verify ... ok
test test::tests::test_sm2_encrypt_decrypt ... ok
test test::tests::test_symmetrickey_generate_key ... ok
test test::tests::test_symmetrickey_encrypt_decrypt ... ok
test test::tests::test_generate_datakey ... ok
test test::tests::test_rsa_encrypt_decrypt ... ok
test test::tests::test_export_datakey ... ok
test test::tests::test_asymmetrickey_generate_key ... ok
test test::tests::test_asymmetrickey_sign_verify ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 47.06s

     Running unittests src/main.rs (target/debug/deps/ehsm_client-afbed2a26774fc60)
```
