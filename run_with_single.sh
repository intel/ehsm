#!/bin/bash

#set -v

EHSM_KMS_PORT="9002"
EHSM_RUN_MODE="single"

EHSM_COUCHDB_IMG="couchdb:3.2"
EHSM_COUCHDB_DOCKER_NAME="c_couchdb"
EHSM_COUCHDB_USER="admin"
EHSM_COUCHDB_PASSWORD="password"
EHSM_COUCHDB_PORT="5984"

# Check if the "couchdb:3.2" image already exists
if ! docker image inspect $EHSM_COUCHDB_IMG >/dev/null 2>&1; then
    # Pull the "couchdb:3.2" image
    docker pull $EHSM_COUCHDB_IMG
    echo "$EHSM_COUCHDB_IMG Docker image pulled."
else
    echo "$EHSM_COUCHDB_IMG Docker image already exists. Nothing to do."
fi

# Check if the "c_couchdb" container already exists
if ! [ "$(docker ps -q -f name=c_couchdb)" ]; then
    # Start a new "c_couchdb" container
    docker run -d -p $EHSM_COUCHDB_PORT:$EHSM_COUCHDB_PORT -e COUCHDB_USER=$EHSM_COUCHDB_USER -e COUCHDB_PASSWORD=$EHSM_COUCHDB_PASSWORD --name $EHSM_COUCHDB_DOCKER_NAME $EHSM_COUCHDB_IMG
    echo "c_couchdb Docker container started."
else
    echo "c_couchdb Docker container already exists. Nothing to do."
fi

# Check if the couchdb is available
if ! [ "$(curl -u $EHSM_COUCHDB_USER:$EHSM_COUCHDB_PASSWORD -X GET http://localhost:$EHSM_COUCHDB_PORT/ehsm_kms_db > /dev/null 2>&1)" ]; then
    echo "$EHSM_COUCHDB_DOCKER_NAME is available."
else
    echo "$EHSM_COUCHDB_DOCKER_NAME is unavailable, please remove it and try again."
    exit 1
fi

# Clean build the EHSM
make clean && make
echo "ehsm clean build done."

# Copy the build binaries to the nodejs folder
cp out/ehsm-core/libehsmprovider.so ehsm_kms_service/
cp out/ehsm-core/libenclave-ehsm-core.signed.so ehsm_kms_service/
echo "ehsm libehsmprovider and libenclave-ehsm-core copied."


if ! [ "$(node -v)" ]; then
    wget https://nodejs.org/dist/v20.1.0/node-v20.1.0-linux-x64.tar.xz \
        && tar xf node-v20.1.0-linux-x64.tar.xz \
        && rm -rf node-v20.1.0-linux-x64.tar.xz \
        && sudo mv node-v20.1.0-linux-x64/ /usr/local/nodejs \
        && sudo ln -s /usr/local/nodejs/bin/node /usr/local/bin \
        && sudo ln -s /usr/local/nodejs/bin/npm /usr/local/bin
fi

# Start the ehsm-kms webserver
cd ehsm_kms_service

if [ ! -d  "node_modules" ]; then
    npm install
fi

sudo node ./ehsm_kms_server.js run_mode=$EHSM_RUN_MODE port=$EHSM_KMS_PORT

