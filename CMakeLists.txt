cmake_minimum_required(VERSION 3.29)
project(micro-deterministic-ecdsa LANGUAGES C)

# Set the C standard to C23
set(CMAKE_C_STANDARD 23)

# Include directories (if you have header files)
include_directories(include)

# Find all source files in the 'src' directory
file(GLOB SOURCES src/**/*.c)

# Create the library target
add_library(micro-deterministic-ecdsa ${SOURCES})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c23")

# Find all test files in the 'test' directory
file(GLOB TEST_SOURCES test/*.c)

# Create an executable for each test file
foreach(test_file IN LISTS TEST_SOURCES)

    # Extract the base filename (without path and extension)
    get_filename_component(test_name ${test_file} NAME_WE)

    # Create the test executable
    add_executable(${test_name} ${test_file})

    # Link the library to the test executable
    target_link_libraries(${test_name} micro-deterministic-ecdsa)

	# Add the test to the test suite
	add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# target_link_libraries(micro-deterministic-ecdsa-test micro-deterministic-ecdsa)
# add_test(NAME TestMicroDeterministicECDSA COMMAND micro-deterministic-ecdsa-test)
enable_testing()

