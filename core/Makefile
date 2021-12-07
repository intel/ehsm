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

include ../buildenv.mk

App_Name := ehsm-core
Enclave_Name := libenclave-$(App_Name).so
Signed_Enclave_Name := libenclave-$(App_Name).signed.so
Napi_Name := libehsmnapi.so
Enclave_Config_File := Enclave/enclave.config.xml
Enclave_Signing_Key := Enclave/enclave_private_test.pem

OUT = $(TOPDIR)/$(OUTDIR)/$(App_Name)

######## App Settings ########
App_Cpp_Files := $(wildcard App/*.cpp)
App_Include_Paths := \
	-I$(SGX_SDK)/include \
	-IInclude \
	-IApp \
	-I$(TOPDIR)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
    App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
    App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
    App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

EHSM_DEFAULT_DOMAIN_KEY_FALLBACK ?= true
ifeq (true, $(EHSM_DEFAULT_DOMAIN_KEY_FALLBACK))
	App_C_Flags += -DEHSM_DEFAULT_DOMAIN_KEY_FALLBACK=1
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L. -lsgx_ukey_exchange -lpthread

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_epid_sim -lsgx_quote_ex_sim
else
	App_Link_Flags += -lsgx_epid -lsgx_quote_ex
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

######## Enclave Settings ########
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(wildcard Enclave/*.cpp)
Enclave_Include_Paths := \
	-I$(SGX_SDK)/include \
	-I$(SGX_SDK)/include/tlibc \
	-I$(SGX_SDK)/include/libcxx \
	-IInclude \
	-IEnclave \
	-I$(TOPDIR)/include

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
	-Wl,--version-script=Enclave/enclave_config/enclave_hsm.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Config_File := Enclave/enclave_config/enclave_hsm.config.xml
######## NAPI Settings ########
Napi_Cpp_Files := App/ehsm_napi.cpp
Napi_Include_Paths := \
	-I$(SGX_SDK)/include \
	-IInclude \
	-IApp \
	-I$(TOPDIR)/include

Napi_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
Napi_Cpp_Flags := $(Napi_C_Flags) -std=c++11
Napi_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L. -lsgx_ukey_exchange -lpthread -nostartfiles -Wl,--export-dynamic -shared

ifneq ($(SGX_MODE), HW)
	Napi_Link_Flags += -lsgx_epid_sim -lsgx_quote_ex_sim
else
	Napi_Link_Flags += -lsgx_epid -lsgx_quote_ex
endif

Napi_Cpp_Objects := $(Napi_Cpp_Files:.cpp=.o)


######## Build Settings ########
.PHONY: all target clean
all: target
	@$(MAKE) target
	@mkdir -p $(OUT)
	@mv $(App_Name) $(Napi_Name) $(Signed_Enclave_Name) $(Enclave_Name) $(OUT)

ifeq ($(Build_Mode), HW_RELEASE)
target: $(App_Name) $(Napi_Name) $(Enclave_Name)
else
target: $(App_Name) $(Napi_Name) $(Signed_Enclave_Name)
endif

clean:
	@rm -f $(App_Cpp_Objects) $(Napi_Cpp_Objects) $(Enclave_Cpp_Objects) App/enclave_hsm_u.* Enclave/enclave_hsm_t.*
	@rm -rf $(OUT)


######## App Objects ########

App/enclave_hsm_u.c: $(SGX_EDGER8R) Enclave/enclave_hsm.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/enclave_hsm.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/enclave_hsm_u.o: App/enclave_hsm_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/enclave_hsm_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

Enclave/enclave_hsm_t.c: $(SGX_EDGER8R) Enclave/enclave_hsm.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/enclave_hsm.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/enclave_hsm_t.o: Enclave/enclave_hsm_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/enclave_hsm_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/enclave_config/enclave_hsm_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

######## NAPI Objects ########
App/ehsm_napi.o: App/ehsm_napi.cpp
	@$(CXX) $(Napi_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Napi_Name): $(Napi_Cpp_Objects) $(App_Cpp_Objects) App/enclave_hsm_u.o
	$(CXX) $^ -o $@ $(Napi_Link_Flags)
	@echo "LINK =>  $@"