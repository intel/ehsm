#!/usr/bin/env bash

set -e

EHSM_DOCKER_IMAGE_NAME="intelccc/ehsm_dkeyserver:0.2.0"
HOST_PORT=8888
DOCKER_PORT=8888
PCCS_URL="https://1.2.3.4:8081"


RUN_ARG="--env http_proxy=$http_proxy --env https_proxy=$https_proxy"
RUN_ARG="$RUN_ARG --device=/dev/sgx/enclave --device=/dev/sgx/provision -v /var/run/aesmd:/var/run/aesmd"

# run the container
echo "docker run -d $RUN_ARG -it -p $HOST_PORT:$DOCKER_PORT -e PCCS_URL=$PCCS_URL $EHSM_DOCKER_IMAGE_NAME"
docker run -d $RUN_ARG -it -p $HOST_PORT:$DOCKER_PORT -e PCCS_URL=$PCCS_URL $EHSM_DOCKER_IMAGE_NAME


exit
