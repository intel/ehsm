#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

LIBNAME := libra_tkey_exchange.a

OUT = $(TOPDIR)/$(OUTLIB_DIR)

Include_Paths := \
	-I$(TOPDIR)/include \
	-I$(TOPDIR)/include/key_exchange \
	-I$(SGX_SDK)/include \
	-I$(SGX_SDK)/include/tlibc \
	-I$(SGX_SDK)/include/libcxx

CXXFLAGS += $(ENCLAVE_CXXFLAGS) $(Include_Paths)

SRC := $(wildcard *.cpp)

OBJ := $(sort $(SRC:.cpp=.o))

.PHONY: all
all: $(LIBNAME)
	@mkdir -p $(OUT)
	@mv $< $(OUT)

sgx_tkey_exchange_t.c: $(SGX_EDGER8R) sgx_tkey_exchange.edl
	@$(SGX_EDGER8R) sgx_tkey_exchange.edl --search-path .
	@echo "GEN  =>  $@"

tkey_exchange.o: sgx_tkey_exchange_t.c
	@$(CC) $(CXXFLAGS) -c $< -o $@
	@echo "CC   <=  $<"

$(OBJ): %.o :%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(LIBNAME): $(OBJ)
	$(AR) rcsD $@ $^

.PHONY: clean
clean:
	@$(RM) $(OBJ)
	@$(RM) sgx_tkey_exchange_t.* sgx_tkey_exchange_u.*
	@$(RM) $(LIBNAME)

