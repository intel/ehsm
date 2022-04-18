FROM ubuntu:18.04

ARG TAG_VERSION=main

RUN apt-get update && apt-get install -y \
    vim \
    autoconf \
    automake \
    build-essential \
    cmake \
    curl \
    debhelper \
    git \
    libcurl4-openssl-dev \
    libprotobuf-dev \
    libssl-dev \
    libtool \
    lsb-release \
    ocaml \
    ocamlbuild \
    protobuf-compiler \
    python \
    wget \
    libcurl4 \
    libprotobuf10 \
    libssl1.1 \
    make \
    module-init-tools \
    g++ \
    libjsoncpp-dev\
    uuid-dev

# Install the SDK
WORKDIR /opt/intel
RUN wget https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.16.100.4.bin \
    && chmod 777 sgx_linux_x64_sdk_2.16.100.4.bin \
    && sh -c 'echo yes | ./sgx_linux_x64_sdk_2.16.100.4.bin'

#Install SDK toolset
RUN wget https://download.01.org/intel-sgx/sgx-linux/2.16/as.ld.objdump.r4.tar.gz \
    && tar -zxf as.ld.objdump.r4.tar.gz \
    && cp external/toolset/ubuntu18.04/* /usr/local/bin

# Install DCAP packages
# DCAP repository setup
RUN wget https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/distro/ubuntu18.04-server/sgx_debian_local_repo.tgz \
    && tar xzf sgx_debian_local_repo.tgz \
    && echo 'deb [trusted=yes arch=amd64] file:///opt/intel/sgx_debian_local_repo bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list \
    && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - \
    && apt-get update

RUN apt-get update &&apt-get install -y \
    libsgx-enclave-common-dev \
    libsgx-ae-qe3 \
    libsgx-ae-qve \
    libsgx-urts \
    libsgx-dcap-ql \
    libsgx-dcap-default-qpl \
    libsgx-dcap-quote-verify-dev \
    libsgx-dcap-default-qpl-dev \
    libsgx-quote-ex-dev  \
    libsgx-uae-service \
    libsgx-ra-network \
    libsgx-ra-uefi \
    libsgx-dcap-ql-dev

# Build App from source
WORKDIR /home
RUN git clone --recursive -b $TAG_VERSION https://github.com/intel/ehsm.git \
    && cd ehsm \
    && make


CMD ["sh", "sleep 10s"]
