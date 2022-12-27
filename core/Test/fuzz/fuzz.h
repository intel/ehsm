#ifndef __FUZZ_H__
#define __FUZZ_H__

#include <unistd.h>
#include <assert.h>
#include <string.h>

#include "../../App/ehsm_provider.h"

void fuzz_one_input(uint8_t* buf);

#endif