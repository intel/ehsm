set -e
docker build --build-arg https_proxy=$https_proxy \
             --build-arg http_proxy=$http_proxy -f ./docker/Dockerfile -t ehsmcore:latest ./

# Another container should expose AESM and its socket in aesmd-socket volume.
# Replace /dev/sgx/enclave with /dev/isgx if you use the Legacy Launch Control driver
docker run --env http_proxy --env https_proxyi --device=/dev/sgx/enclave -v aesmd-socket:/var/run/aesmd -it -P ehsmcore

