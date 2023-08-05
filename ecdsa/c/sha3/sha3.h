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

#define decshake(bits) int shake##bits(uint8_t *, size_t, const uint8_t *, size_t);

#define decsha3(bits) int sha3_##bits(uint8_t *, size_t, const uint8_t *, size_t);

decshake(128) decshake(256) decsha3(224) decsha3(256) decsha3(384) decsha3(512)

	int sha3_ethereum256(uint8_t *, size_t, const uint8_t *, size_t);

#endif /* sha3_h */
