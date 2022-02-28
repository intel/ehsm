FROM ubuntu:18.04 as sample

ENV PCCS_URL https://10.112.240.166:8081

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
RUN wget https://download.01.org/intel-sgx/sgx-dcap/1.12.1/linux/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.15.101.1.bin \
    && chmod 777 sgx_linux_x64_sdk_2.15.101.1.bin \
    && sh -c 'echo yes | ./sgx_linux_x64_sdk_2.15.101.1.bin'

# Install DCAP packages
# DCAP repository setup
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list \
    && wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -

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


# RESET PCCS URL
WORKDIR /etc
RUN echo '# PCCS server address' > sgx_default_qcnl.conf \
    && echo 'PCCS_URL='${PCCS_URL}'/sgx/certification/v3/' >> sgx_default_qcnl.conf \
    && echo '# To accept insecure HTTPS certificate, set this option to FALSE' >> sgx_default_qcnl.conf \
    && echo 'USE_SECURE_CERT=FALSE' >> sgx_default_qcnl.conf


# Build App from source
WORKDIR /home
RUN git clone https://github.com/intel/ehsm.git \
    && cd ehsm \
    && make

# image port
EXPOSE 8888

# run ehsm-dkeyserver
CMD ["./ehsm/out/ehsm-dkeyserver/ehsm-dkeyserver"]


