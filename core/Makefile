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
App_Test_Name := ehsm_core_test
Enclave_Name := libenclave-$(App_Name).so
Signed_Enclave_Name := libenclave-$(App_Name).signed.so
Provider_Name := libehsmprovider.so
Enclave_Config_File := Enclave/enclave.config.xml
Enclave_Signing_Key := Enclave/enclave_private_test.pem
Sgx_Signing_tool := $(SGX_SDK)/bin/x64/sgx_sign

ENABLE_PERFORMANCE_TEST ?= 0

ENABLE_SELF_TEST ?= 0

ENABLE_PAIR_WISE_TEST ?= 0

OUT = $(TOPDIR)/$(OUTDIR)/$(App_Name)
Signed_Enclave_FileName := $(OUT)/$(Signed_Enclave_Name)

######## App Settings ########
App_Cpp_Files := $(wildcard App/*.cpp)
App_Cpp_Files += $(wildcard $(LOG_DIR)/*.cpp)
App_Include_Paths := \
	-I$(SGX_SDK)/include \
	-IApp \
	-I$(LOG_DIR) \
	-I$(TOPDIR)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) -DEHSM_RUNTIME_FOLDER=\"$(EHSM_RUNTIME_FOLDER)\" -DEHSM_LOCAL_DATA_FOLDER=\"$(EHSM_LOCAL_DATA_FOLDER)\" -DEHSM_LOGS_FOLDER=\"$(EHSM_LOGS_FOLDER)\" -DSIGNED_ENCLAVE_FILENAME=\"$(Signed_Enclave_FileName)\" -DSGX_SIGNING_TOOL=\"$(Sgx_Signing_tool)\"
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

ifeq (1, $(ENABLE_PERFORMANCE_TEST))
	App_C_Flags += -DENABLE_PERFORMANCE_TEST
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread -ljsoncpp -luuid -L$(OPENSSL_LIBRARY_PATH) -l$(SGXSSL_Untrusted_Library_Name) -llog4cplus

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_epid_sim -lsgx_quote_ex_sim
else
	App_Link_Flags += -lsgx_quote_ex -lsgx_uae_service -lsgx_dcap_ql -lsgx_dcap_quoteverify -ldl
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

######## App Test Settings ########
App_Test_Cpp_Files := $(wildcard Test/*.cpp)
App_Test_Cpp_Objects := $(App_Test_Cpp_Files:.cpp=.o)

######## Enclave Settings ########
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := $(wildcard Enclave/*.cpp)
Enclave_Cpp_Files += $(wildcard Enclave/self_test/*.cpp)
Enclave_Include_Paths := \
	-I$(SGX_SDK)/include \
	-I$(SGX_SDK)/include/tlibc \
	-I$(SGX_SDK)/include/libcxx \
	-IInclude \
	-IEnclave \
	-IEnclave/self_test \
	-I$(LOG_DIR) \
	-I$(TOPDIR)/include \
	-I$(OPENSSL_PATH)/include

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths) 

ifeq ($(ENABLE_SELF_TEST), 1)
	Enclave_C_Flags += -DENABLE_SELF_TEST
endif

ifeq ($(ENABLE_PAIR_WISE_TEST), 1)
	Enclave_C_Flags += -DENABLE_PAIR_WISE_TEST
endif

Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++ -include "tsgxsslio.h"

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	$(SgxSSL_Link_Libraries) \
	-Wl,--whole-archive -lsgx_dcap_tvl -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=Enclave/enclave_config/enclave_hsm.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Config_File := Enclave/enclave_config/enclave_hsm.config.xml


######## Build Settings ########
.PHONY: all target clean
all: target
	@$(MAKE) target
	@echo $(EHSM_DEFAULT_DOMAIN_KEY_FALLBACK)
	@mkdir -p $(OUT)
	@mv $(Provider_Name) $(Signed_Enclave_Name) $(Enclave_Name) $(App_Test_Name) $(OUT)

ifeq ($(Build_Mode), HW_RELEASE)
target: $(Provider_Name) $(Enclave_Name) $(App_Test_Name)
else
target: $(Provider_Name) $(Signed_Enclave_Name) $(App_Test_Name)
endif

clean:
	@rm -f $(App_Cpp_Objects) $(App_Test_Cpp_Objects) $(Enclave_Cpp_Objects) App/auto_version.h App/enclave_hsm_u.* Enclave/enclave_hsm_t.*
	@rm -rf $(OUT)


######## App Objects ########
App/auto_version.h:
	@`touch App/auto_version.h`
	@echo "#ifndef EHSM_CORE_AUTO_VERSION_H" > App/auto_version.h
	@echo "#define EHSM_CORE_AUTO_VERSION_H" >> App/auto_version.h
	@echo "#define EHSM_VERSION \"$(VERSION_STRING)\"" >> App/auto_version.h
	@echo "#define EHSM_DATE \"$(DATE_STRING)\""	>> App/auto_version.h
	@echo "#define EHSM_GIT_SHA \"$(EHSM_KMS_GIT_SHA)\""	>> App/auto_version.h
	@echo "#endif //EHSM_CORE_AUTO_VERSION_H"	>> App/auto_version.h
	@echo "  ==>  touch App/auto_version.h"

App/enclave_hsm_u.c: $(SGX_EDGER8R) Enclave/enclave_hsm.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/enclave_hsm.edl --search-path ../Enclave --search-path ../Enclave/self_test --search-path $(SGX_SDK)/include --search-path $(OPENSSL_PATH)/include --search-path $(LOG_DIR)
	@echo "GEN  =>  $@"

App/enclave_hsm_u.o: App/enclave_hsm_u.c
	@$(CXX) $(App_C_Flags) -c $< -o $@
	@echo "CXX   <=  $<"

App/%.o: App/%.cpp App/auto_version.h App/enclave_hsm_u.c
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(LOG_DIR)/%.o: $(LOG_DIR)/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Test/%.o: Test/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Provider_Name): $(App_Cpp_Objects) App/enclave_hsm_u.o App/auto_version.h
	@$(CXX) $^ -o $@ $(App_Link_Flags) -shared
	@echo "LINK =>  $@"

$(App_Test_Name): $(App_Cpp_Objects) $(App_Test_Cpp_Objects) App/enclave_hsm_u.o App/auto_version.h
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

Enclave/enclave_hsm_t.h: $(SGX_EDGER8R) Enclave/enclave_hsm.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/enclave_hsm.edl --search-path ../Enclave --search-path ../Enclave/self_test --search-path $(SGX_SDK)/include --search-path $(OPENSSL_PATH)/include
	@echo "GEN  =>  $@"

Enclave/enclave_hsm_t.c: Enclave/enclave_hsm_t.h

Enclave/enclave_hsm_t.o: Enclave/enclave_hsm_t.c
	@$(CXX) $(Enclave_C_Flags) -c $< -o $@
	@echo "CXX   <=  $<"

Enclave/%.o: Enclave/%.cpp Enclave/enclave_hsm_t.h
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Enclave/enclave_hsm_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@$(SGX_ENCLAVE_SIGNER) sign -key Enclave/enclave_config/enclave_hsm_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"
