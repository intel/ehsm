# eHSM Python SDK

## Dependencies

- Python 3.8 or above
- [httpx](https://www.python-httpx.org/) - A next-generation HTTP client for Python.
- [pydantic](https://github.com/pydantic/pydantic) - Data validation using Python type hints
- [click](https://click.palletsprojects.com/) - A Python package for creating beautiful command line interfaces
- [pytest](https://github.com/pytest-dev/pytest) - A framework makes it easy to write small tests, yet scales to support complex functional testing

## Install

Run the following command to install this package:

```bash
# Option 1: install from local file
pip install .
# Optoin 2: install from official github repository
pip install "git+https://github.com/intel/ehsm.git#subdirectory=sdk/python"
```

## Usage

The `ehsm` package provides API client and a CLI application.

### Command Line Interface (CLI)

The CLI wraps all API provided by eHSM service. The CLI can be invoked by `ehsm` or `python -m ehsm` after installation.

The format of command is as below.

```bash
ehsm --url <ehsm_service_url> <action> <action_args>
# Run the following command to get full supported API list
ehsm --help
```

Global options (`--appid`, `--apikey`, `-url` and `--insecure`) can be specified using environmental variables (instead of explicitly specified in command). The mapping of global options and environmental variables are:

- `--url`: `EHSM_SERVER_URL`
- `--appid`: `EHSM_APPID`
- `--apikey`: `EHSM_APIKEY`
- `--insecure`: `EHSM_INSECURE`

Some examples are listed below.

```bash
# enroll for getting appid and apikey
ehsm --url https://127.0.0.1:9002/ehsm --insecure enroll

# create key (with url/appid/apikey specified in command explicitly)
ehsm --url https://127.0.0.1:9002/ehsm --insecure \
    --appid b7c62e4d-c238-4016-b35f-47bc4b57dc03 \
    --apikey D3nK2Vq90QrFkHGRZ3dBAyFEfPTtLfQy \
    create-key \
    --keyspec EH_AES_GCM_128 \
    --origin EH_INTERNAL_KEY \
    --keyusage EH_KEYUSAGE_ENCRYPT_DECRYPT

# create key (with url/appid/apikey specified in env vars)
export EHSM_SERVER_URL=https://127.0.0.1:9002/ehsm
export EHSM_APPID=b7c62e4d-c238-4016-b35f-47bc4b57dc03
export EHSM_APIKEY=D3nK2Vq90QrFkHGRZ3dBAyFEfPTtLfQy

ehsm --insecure create-key \
    --keyspec EH_AES_GCM_128 \
    --origin EH_INTERNAL_KEY \
    --keyusage EH_KEYUSAGE_ENCRYPT_DECRYPT
```

### eHSM API Client

The API client provides an unified entry for calling eHSM APIs programmatically. The basic usage is as following:

```python
from ehsm import Client
from ehsm.api.enums import KeySpec, Origin, KeyUsage

# you may also provides appid and apikey as argument of `Client` constructor
client = Client(base_url="https://127.0.0.1:9002/ehsm", allow_insecure=True)
# the appid and apikey is automatically saved inside `client` instance
appid, apikey = client.enroll()

# Init client with given appid and apikey is also allowed
# client = Client(
#   base_url="https://127.0.0.1:9002/ehsm",
#   allow_insecure=True,
#   appid="8d24ea9b-1531-41d9-8445-750c5bdf2b34",
#   apikey="fNbseLfj9JQWMfMGeN20PeZJZwK5isBU",
# )

result = client.create_key(
    KeySpec.EH_AES_GCM_128, Origin.EH_INTERNAL_KEY, KeyUsage.EH_KEYUSAGE_ENCRYPT_DECRYPT
)
print("key_id is", result.keyid)

# getting the response
print(result.repsonse.code)
print(result.repsonse.message)
print(result.raw_response)  # access raw response object
```

The supported APIs are listed in [eHSM APIs docs](https://github.com/intel/ehsm/blob/main/docs/API_Reference.md).

**Note:** the function names (e.g. `createKey`), input and output params (e.g. `keyId`) are converted to snake case in Python SDK. For example, you need to access `result.expire_time` instead of `result.expireTime` for getting the expire time of a  key.

## Develop

### Environment Setup

#### Installation

This project uses [pdm](https://github.com/pdm-project/pdm) for managing dependencies. You can install [pdm](https://github.com/pdm-project/pdm) using following command:

```bash
curl -sSL https://pdm-project.org/install-pdm.py | python3 -
```

More installation methods are provided on [PDM's Github repository](https://github.com/pdm-project/pdm).

After installing `pdm`, run the following command to turn current directory to editable package:

```bash
pdm install
```

#### Build

You may use the following command to build `sdist` and `wheel`:

```bash
pdm build
```

### Project Structure

This project encapsulates eHSM KMS server APIs, provides an developer-friendly unified interface (APIClient) for invoking these APIs. The project structure is listed as following:

```text
.
├── ehsm
│   ├── api (API client)
│   ├── cli (CLI interface)
│   ├── serializers (Definition of response type)
│   └── server_tests (Tests for eHSM KMS server)
└── tests (unused tests directory)
```

#### API Client

The `api` package has 4 subpackages, corresponding to APIs with different functionalities. The `EHSMBaseClient` has a `Session` member. `Session` signs the requests to eHSM KMS server and is responsible for dealing with `appid` and `apikey`.

The 4 subpackages (`crypto`, `key_management`, `remote_attestation` and `secret_management`) are combined to the `Client` class as mixins.

#### CLI Interface

The CLI interface encapsulates APIs, pass params in command line as the arguments of API client function call and provides help messages for the params. The CLI interface is a `click` application. The structure is as following:

- crypto (counterpart of `crypto` in API)
- key management (counterpart of `key_management` in API)
- remote attestation (counterpart of `remote_attestation` in API)
- secret management (counterpart of `secret_management` in API)
- options (definition of the command line arguments and help messages)
- server test (invoke `pytest` in `server_tests` through command line)
- utils (helper functions)

#### Serializers

Serializers defines the structure of responses of all API calls using `pydantic` package. All response structures are defined as a pydantic model.

The `EHSMResponse` provides common fields (`code` and `message`) in of API responses from eHSM KMS server.

`EHSMBase` class is the base class for all serializers (the defined responses). The `EHSMBase.from_response()` method validates and serializes the API response, and constructs an pydantic object based on the response.

#### Server Tests

> **Note:** Server tests module will NOT cleanup the created resources (e.g. appid, keys), **DO NOT USE** in production environment

Server tsets module is a `pytest` module for testing the functionalities of **eHSM KMS server** (NOT API client). This module should be useful when trying to verify the eHSM KMS server generate correct response in development and deployment.

Server tests module is based on the API client. It is also a collection of examples of the API client.

Server tests module can be invoked by the CLI interface by following command:

```bash
# make sure run `pdm install` before running following commands
ehsm --url https://127.0.0.1:9002/ehsm --insecure server-test --enroll
```

The command above will enroll a `appid, apikey` pair before running each test. It is also possible to provide `appid` and `apikey` instead of enrolling every test:

```bash
# make sure run `pdm install` before running following commands
ehsm --url https://127.0.0.1:9002/ehsm \
    --appid b7c62e4d-c238-4016-b35f-47bc4b57dc03 \
    --apikey D3nK2Vq90QrFkHGRZ3dBAyFEfPTtLfQy \
    --insecure server-test
```

> **Note:** Using the same key for all tests may causes some tests failed since these tests (e.g. `test_list_key()`) may assume the `appid` has no resource before running test.

The CLI command also supports passing additional params to `pytest` by specifying `--extra` argument.

```bash
ehsm --url https://127.0.0.1:9002/ehsm --insecure server-test --extra="-v" --enroll
```

The server tests module is consists of four submodules (`test_crypto.py`, `test_key_management.py`, `test_remote_attestation.py`, `test_secret_management.py`), which corresponding to four functionalities API modules. Testing submodule individually is supported by using `--path` option. In additional, the `--path` option can be used to test only one method.

The following is an example if you want to run `test_sign_verify()` in `test_crypto.py` module only.

```bash
# run test_list_key() in `test_sign_verify.py` only
ehsm --url https://127.0.0.1:9002/ehsm --insecure server-test --path="test_crypto.py::test_list_key" --enroll
```
