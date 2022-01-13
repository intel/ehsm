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

include ../../buildenv.mk

App_Name := enroll

OUT = $(TOPDIR)/$(OUTDIR)/$(App_Name)

######## App Settings ########
App_Cpp_Files := $(wildcard ./*.cpp)
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
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -L. -lsgx_ukey_exchange -lpthread -ljsoncpp -lcurl

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_epid_sim -lsgx_quote_ex_sim
else
	App_Link_Flags += -lsgx_epid -lsgx_quote_ex
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)


######## Build Settings ########
.PHONY: all target clean

all: $(App_Name)
	@$(MAKE) target
	@mkdir -p $(OUT)
	@mv $(App_Name) $(OUT)
	@cp config.json $(OUT)

ifeq ($(Build_Mode), HW_RELEASE)
target: $(App_Name)
else
target: $(App_Name)
endif

clean:
	@rm -f $(App_Cpp_Objects)
	@rm -rf $(OUT)

######## App Objects ########
main.o: main.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"
$(App_Name): main.o
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo :"Link =>  $@"
