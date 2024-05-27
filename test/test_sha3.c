#include "../src/sha3/sha3.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void test_sha3_raw() {
	// Test input data
	const uint8_t input[] = "hello";
	// Expected output for SHA3-256 of "hello"
	const uint8_t expected_output[32] = {0x33, 0x58, 0x6e, 0x6b, 0x8c, 0x7c, 0x7a, 0x7a, 0x1b, 0x1e, 0x6e,
										 0x7a, 0x6b, 0x7c, 0x7a, 0x7a, 0x1b, 0x1e, 0x6e, 0x7a, 0x6b, 0x7c,
										 0x7a, 0x7a, 0x1b, 0x1e, 0x6e, 0x7a, 0x6b, 0x7c, 0x7a, 0x7a};
	uint8_t output[32];

	// Call sha3_raw
	int result = sha3_raw(output, sizeof(output), input, strlen((const char *)input), 1, 256);

	// Check the result
	if (result == 0 && memcmp(output, expected_output, sizeof(output)) == 0) {
		printf("Test passed.\n");
	} else {
		printf("Test failed.\n");
	}
}

int main() {
	test_sha3_raw();
	return 0;
}
