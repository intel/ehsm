#
# Copyright (C) 2020-2021 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= SIM
SGX_ARCH ?= x64

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -ggdb3
else
        SGX_COMMON_CFLAGS += -O2
endif

ifeq ($(SUPPLIED_KEY_DERIVATION), 1)
        SGX_COMMON_CFLAGS += -DSUPPLIED_KEY_DERIVATION
endif

######## Untrusted Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

Untrusted_Cpp_Files := untrusted/EHsmProvider.cpp untrusted/EnclaveHelpers.cpp
Untrusted_Include_Paths := -I$(SGX_SDK)/include -Itrusted

Untrusted_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Untrusted_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        Untrusted_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        Untrusted_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        Untrusted_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

Untrusted_Cpp_Flags := $(Untrusted_C_Flags) -std=c++11
Untrusted_Link_Flags := -lcurl -ljsoncpp -shared $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L. -lsgx_ukey_exchange -lpthread

ifneq ($(SGX_MODE), HW)
	Untrusted_Link_Flags += -lsgx_epid_sim -lsgx_quote_ex_sim
else
	Untrusted_Link_Flags += -lsgx_epid -lsgx_quote_ex
endif

Untrusted_Cpp_Objects := $(Untrusted_Cpp_Files:.cpp=.o)

Untrusted_Name := libEHsm.so

######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(wildcard trusted/*.cpp)
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=trusted/enclave_hsm.lds 

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := libSgxHsmEnclave.so
Signed_Enclave_Name := libSgxHsmEnclave.signed.so
Enclave_Config_File := trusted/enclave_hsm.config.xml

ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
Build_Mode = HW_RELEASE
endif
endif
endif


.PHONY: all

ifeq ($(Build_Mode), HW_RELEASE)
all: $(Untrusted_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the App to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
all: $(Untrusted_Name) $(Signed_Enclave_Name)
endif

######## Untrusted Objects ########

untrusted/enclave_hsm_u.c: $(SGX_EDGER8R) trusted/enclave_hsm.edl
	@cd untrusted && $(SGX_EDGER8R) --untrusted ../trusted/enclave_hsm.edl --search-path ../trusted --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

untrusted/enclave_hsm_u.o: untrusted/enclave_hsm_u.c
	@$(CC) $(Untrusted_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

untrusted/%.o: untrusted/%.cpp
	@$(CXX) $(Untrusted_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Untrusted_Name): untrusted/enclave_hsm_u.o $(Untrusted_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Untrusted_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

trusted/enclave_hsm_t.c: $(SGX_EDGER8R) trusted/enclave_hsm.edl
	@cd trusted && $(SGX_EDGER8R) --trusted ../trusted/enclave_hsm.edl --search-path ../trusted --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

trusted/enclave_hsm_t.o: trusted/enclave_hsm_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

trusted/%.o: trusted/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): trusted/enclave_hsm_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key trusted/enclave_hsm_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

release: all
	@mkdir -p release
	@cp $(Signed_Enclave_Name) release
	@cp untrusted/EHsmProvider.h release
	@cp lib*.so release

.PHONY: clean

clean:
	@rm -f release/*.* $(Enclave_Name) $(Signed_Enclave_Name) $(Untrusted_Cpp_Objects) $(Untrusted_Name) untrusted/enclave_hsm_u.* $(Enclave_Cpp_Objects) trusted/enclave_hsm_t.*
