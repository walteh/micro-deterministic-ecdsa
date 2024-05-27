#include "../src/keccak256/keccak256.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main() {
	// Test input data
	const uint8_t input[] = "hello";
	// Expected output for keccak256("hello")
	// 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
	const uint8_t expected_output[32] = {0x1c, 0x8a, 0xff, 0x95, 0x06, 0x85, 0xc2, 0xed, 0x4b, 0xc3, 0x17,
										 0x4f, 0x34, 0x72, 0x28, 0x7b, 0x56, 0xd9, 0x51, 0x7b, 0x9c, 0x94,
										 0x81, 0x27, 0x31, 0x9a, 0x09, 0xa7, 0xa3, 0x6d, 0xea, 0xc8};
	uint8_t output[32];

	// Call sha3_raw
	int result = sha3_raw(output, sizeof(output), input, strlen((const char *)input), 1, 256);

	// Check the result
	if (result == 0 && memcmp(output, expected_output, sizeof(output)) == 0) {
		printf("Test passed.\n");
		return 0;
	} else {
		printf("Test failed.\n");

		// Print the expected output
		printf("Expected output: ");
		for (int i = 0; i < sizeof(expected_output); i++) {
			printf("%02x", expected_output[i]);
		}
		printf("\n");

		// Print the actual output
		printf("Actual output: ");
		for (int i = 0; i < sizeof(output); i++) {
			printf("%02x", output[i]);
		}

		printf("\n");
		return 1;
	}
}
