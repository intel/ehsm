# Build-Instructions

Welcome to see the build instructions for the ehsm-kms project.

## Quick start with Docker

* Install SGX SDK

```shell
$ wget https://download.01.org/intel-sgx/sgx-dcap/1.12.1/linux/distro/ubuntu20.04-server/sgx_linux_x64_sdk_2.15.101.1.bin

# choose to install the sdk into the /opt/intel
$ chmod a+x ./sgx_linux_x64_sdk_2.15.101.1.bin && sudo ./sgx_linux_x64_sdk_2.15.101.1.bin

$ source /opt/intel/sgxsdk/environment
```

* Build the ehsm-kms docker image
```shell
$ git clone https://github.com/intel/ehsm.git ehsm && cd ehsm

$ ./docker/build_and_run.sh -b

it will generate the docker image <ehsm_kms_service.tar.gz> under your workdir.
```
* Run the ehsm-kms service with docker
```shell
$ ./docker/build_and_run.sh -r 
or
$ ./docker/build_and_run.sh -r ehsm_kms_service.tar.gz

$ docker ps
CONTAINER ID   IMAGE                     COMMAND                  CREATED         STATUS         PORTS                                       NAMES
6b0f786713e5   ehsm_kms_service:latest   "node ehsm_kms_serve…"   8 seconds ago   Up 6 seconds   0.0.0.0:9000->9000/tcp, :::9000->9000/tcp   tender_spence
```

* Run the unit-test cases (you can do it in another remote device)
```
$ cd ehsm_kms_service/test
$ python3 test_kms_with_rest.py -i <your-kms-docker-ip> -p <your-kms-port>
```
Then, you will get the below test result:<br>
![unittest-result-with-rest.png](diagrams/unittest-result-with-rest.PNG)


## Build and Run without Docker

The following steps have been verified on ubuntu-20.04.

* Install the requirement tools

``` shell
$ sudo apt update

$ sudo apt install vim autoconf automake build-essential cmake curl debhelper git libcurl4-openssl-dev libprotobuf-dev libssl-dev libtool lsb-release ocaml ocamlbuild protobuf-compiler wget libcurl4 libssl1.1 make g++ fakeroot libelf-dev libncurses-dev flex bison libfdt-dev libncursesw5-dev pkg-config libgtk-3-dev libspice-server-dev libssh-dev python3 python3-pip  reprepro unzip libjsoncpp-dev
```

*  Install SGX DCAP Driver (**optional**)
    * The DCAP Driver is the recommended driver to use on the Linux kernel version between 4.15 and 5.6 inclusive and on platforms that support and are configured for Flexible Launch Control.
    * Installing DCAP driver on **kernel 5.11 or higher** with SGX In-Kernel driver gives the build error message, "Can't install DCAP SGX driver with inkernel SGX support".

``` shell
$ wget https://download.01.org/intel-sgx/sgx-dcap/1.12.1/linux/distro/ubuntu20.04-server/sgx_linux_x64_driver_1.41.bin

$ chmod a+x sgx_linux_x64_driver_1.41.bin

$ sudo apt install dkms

$ sudo ./sgx_linux_x64_driver_1.41.bin

```

* Install DCAP required packages
```shell
$ echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list

$ wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -

$ sudo apt-get update

$ sudo apt-get install -y libsgx-enclave-common-dev  libsgx-ae-qe3 libsgx-ae-qve libsgx-urts libsgx-dcap-ql libsgx-dcap-default-qpl libsgx-dcap-quote-verify-dev libsgx-dcap-ql-dev libsgx-dcap-default-qpl-dev libsgx-quote-ex-dev libsgx-uae-service libsgx-ra-network libsgx-ra-uefi
```

* Build the eHSM-KMS
```shell
$ git clone https://github.com/intel/ehsm.git ehsm && cd ehsm

$ make

Notes: you can find the services binaries under the bin/ folder 
```
* Unittest w/o REST Call
```shell
$ cd bin/ehsm-core
$ ./ehsm_core_test
```
Then, you will get the below test result:<br>
![unittest-result-without-rest.png](diagrams/unittest-result-without-rest.PNG)


* Unittest w/ REST Call
```shell
# Install nodejs-16
$  sudo apt install -y curl
$ curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
$ sudo apt update
$ sudo apt install -y nodejs
$ node --version
v16.1.0

# Copy the required *.so to the ehsm_kms_service
$ cd ehsm_kms_service
$ cp ../bin/ehsm-core/libehsmnapi.so .
$ cp ../bin/ehsm-core/libenclave-ehsm-core.signed.so .

# Install the required npm js libs for the kms service
$ npm install

# Start the kms service (if you got "Error: listen EADDRINUSE: address already in use :::9000", please close the previous service or containers)
$ node ehsm_kms_server.js &

# Run the unittest cases (you can do it in another remote device)
$ cd ehsm_kms_service/test
$ python3 test_kms_with_rest.py -i <your-kms-docker-ip> -p <your-kms-port>
```

Then, you will get the below test result:<br>
![unittest-result-with-rest.png](diagrams/unittest-result-with-rest.PNG)


Notes:
If you want to deploy the ehsm-kms service into the K8S environment, please refer to the doc [deployment-instructions](deployment-instructions.md).

