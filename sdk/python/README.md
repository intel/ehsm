# eHSM Python SDK

## Dependencies

- Python 3.8 or above
- [httpx](https://www.python-httpx.org/) - A next-generation HTTP client for Python.
- [pydantic](https://github.com/pydantic/pydantic) - Data validation using Python type hints
- [click](https://click.palletsprojects.com/) - A Python package for creating beautiful command line interfaces
- [pytest](https://github.com/pytest-dev/pytest) - A framework makes it easy to write small tests, yet scales to support complex functional testing

## Install

This project is built by [PDM](https://pdm-project.org/).

### Install PDM

```bash
curl -sSL https://pdm-project.org/install-pdm.py | python3 -
```

More installation methods are provided on [PDM's Github repository](https://github.com/pdm-project/pdm).

### Build and Install

```bash
pdm build
pdm install
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

### API Client

The API client provides an unified entry for calling eHSM APIs programmatically. The basic usage is as following:

```python
from ehsm import Client
from ehsm.api.enums import KeySpec, Origin, KeyUsage

# you may also provides apikey and appid as argument of `Client` constructor
client = Client()
# the appid and apikey is automatically saved inside `client` instance
appid, apikey = client.enroll()

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

**Note:** the function names (e.g. `createKey`), input and output params (e.g. `keyId`) are converted to snake case in Python SDK. For example, you need to access `result.key_id` instead of `result.keyId` for getting the key id.
