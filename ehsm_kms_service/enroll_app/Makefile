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

App_Name := ehsm-kms_enroll_app

OUT = $(TOPDIR)/$(OUTDIR)/$(App_Name)

######## App Settings ########
App_Cpp_Files := $(wildcard ./*.cpp)
App_Include_Paths := \
	-I$(SGX_SDK)/include \
	-I$(TOPDIR)/include \
	-Isample_libcrypto

App_Cpp_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths) -std=c++14
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) \
		-L. \
		-lpthread \
		-lsgx_dcap_quoteverify \
		-ldl \
		-ljsoncpp \
		-lcurl \
		-lsample_libcrypto -Lsample_libcrypto -Wl,-rpath=$(CURDIR)/sample_libcrypto

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)


######## Build Settings ########
.PHONY: all target clean

all: target
	@$(MAKE) target
	@mkdir -p $(OUT) && mv $(App_Name) $(OUT)

target: $(App_Name)

clean:
	@rm -f $(App_Cpp_Objects)
	@rm -rf $(OUT)

######## AppObjects ########
%.o: %.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"
	
$(App_Name): $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo :"Link =>  $@"
