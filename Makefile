#
# Copyright (C) 2011-2022 Intel Corporation. All rights reserved.
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

include buildenv.mk

SUB_DIR := utils/tkey_exchange utils/ukey_exchange core dkeycache dkeyserver enroll_app
SSL_DIR := third_party/intel-sgx-ssl
export DESTDIR = ${OPENSSL_PATH}

.PHONY: all clean

all: ssl
	for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir || exit 1; \
	done

ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in hardware debug mode."
else ifeq ($(Build_Mode), HW_RELEAESE)
	@echo "The project has been built in hardware release mode."
else ifeq ($(Build_Mode), HW_PRERELEAESE)
	@echo "The project has been built in hardware pre-release mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in simulation debug mode."
else ifeq ($(Build_Mode), SIM_RELEAESE)
	@echo "The project has been built in simulation release mode."
else ifeq ($(Build_Mode), SIM_PRERELEAESE)
	@echo "The project has been built in simulation pre-release mode."
endif

ssl:
ifeq ("$(wildcard $(SSL_DIR/Linux))", "")
	@git submodule update --init --recursive
endif
ifeq ("$(wildcard $(DESTDIR))", "")
	@wget https://www.openssl.org/source/openssl-1.1.1t.tar.gz -P $(SSL_DIR)/openssl_source/ || exit 1
	$(MAKE) -C $(SSL_DIR)/Linux clean all install || exit 1
	$(MAKE) -C $(SSL_DIR)/Linux clean
	@rm -rf $(SSL_DIR)/openssl_source/openssl-1.1.1* $(SSL_DIR)/Linux/package/include/crypto
endif

clean:
	@rm -rf $(OUTDIR)
	for dir in $(SUB_DIR); do \
		$(MAKE) -C $$dir clean; \
	done
