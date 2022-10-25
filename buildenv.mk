#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
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

######## version ########
vsn_major=0
vsn_minor=2
vsn_patch=1

######## auto_version Settings ########
VERSION_STRING := $(vsn_major).$(vsn_minor).$(vsn_patch)
DATE_STRING := `date "+20%y.%m.%d %k:%M"`
EHSM_KMS_GIT_SHA=$(shell git rev-parse --short=7 --verify HEAD)

# -------------------------------------------------------------------
#  Function : parent-dir
#  Arguments: 1: path
#  Returns  : Parent dir or path of $1, with final separator removed.
# -------------------------------------------------------------------
parent-dir = $(patsubst %/,%,$(dir $(1:%/=%)))

# ------------------------------------------------------------------
#  Macro    : my-dir
#  Returns  : the directory of the current Makefile
#  Usage    : $(my-dir)
# ------------------------------------------------------------------
my-dir = $(realpath $(call parent-dir,$(lastword $(MAKEFILE_LIST))))

ROOT_DIR := $(call my-dir)
ifneq ($(words $(subst :, ,$(ROOT_DIR))), 1)
  $(error main directory cannot contain spaces nor colons)
endif

######## Output Settings ########
TOPDIR = $(ROOT_DIR)
OUTDIR := out
OUTLIB_DIR := $(OUTDIR)/lib

######## Compiler Settings ########
CP = cp
CC ?= gcc
CXX ?= g++
RM = rm -f

######## SGX SSL Settings ########
OPENSSL_PATH := $(ROOT_DIR)/utils/sgxssl
OPENSSL_LIBRARY_PATH := $(OPENSSL_PATH)/lib64
SOCKET_DIR := $(ROOT_DIR)/utils/sgx_socket
SGXSSL_Library_Name := sgx_tsgxssl
OpenSSL_Crypto_Library_Name := sgx_tsgxssl_crypto
SGXSSL_Untrusted_Library_Name := sgx_usgxssl
OpenSSL_SSL_Library_Name := sgx_tsgxssl_ssl

SgxSSL_Link_Libraries := -L$(OPENSSL_LIBRARY_PATH) -Wl,--whole-archive -l$(SGXSSL_Library_Name) -Wl,--no-whole-archive \
			-l$(OpenSSL_SSL_Library_Name) -l$(OpenSSL_Crypto_Library_Name) -lsgx_pthread

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
#SUPPLIED_KEY_DERIVATION ?= 1

include $(SGX_SDK)/buildenv.mk

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SUPPLIED_KEY_DERIVATION), 1)
	SGX_COMMON_FLAGS += -DSUPPLIED_KEY_DERIVATION
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_FLAGS += -O0 -ggdb3
else
    SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
    -Waddress -Wsequence-point -Wformat-security \
    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
    -Wcast-align -Wredundant-decls

#SGX_COMMON_CFLAGS += $(SGX_COMMON_FLAGS) -Wstrict-prototypes -Wunsuffixed-float-constants -Wcast-qual

SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

######## BUILD Settings ########
ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

