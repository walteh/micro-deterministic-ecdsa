//
//  sha3.c
//
//  Created by walteh on 11/23/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
// ---------------------------------------------------------------------
//  adapted from keccak-tiny
//  Copyright © David Leon Gily. CC0 license
// ---------------------------------------------------------------------
//
//  A single-file implementation of SHA-3 and SHAKE
//

#ifndef sha3_h
#define sha3_h

#define __STDC_WANT_LIB_EXT1__ 1
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

int sha3_raw(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen, int opt, int bits);

#endif /* sha3_h */
