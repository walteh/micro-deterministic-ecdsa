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

#define decsha3(bits)                                                     \
	int sha3_raw_##bits(uint8_t *, size_t, const uint8_t *, size_t, int); \
	int sha3_std_##bits(uint8_t *, size_t, const uint8_t *, size_t);      \
	int sha3_eth_##bits(uint8_t *, size_t, const uint8_t *, size_t);

decsha3(224) decsha3(256) decsha3(384) decsha3(512)

#endif /* sha3_h */
