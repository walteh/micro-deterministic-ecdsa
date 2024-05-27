cmake_minimum_required(VERSION 3.15)
project(YourProjectName VERSION 1.0 LANGUAGES C)

# Specify the version of the project.
set(PROJECT_VERSION_MAJOR 1)
set(PROJECT_VERSION_MINOR 0)

# Define the library
add_library(MicroDeterministicECDSA STATIC
    src/rfc6979/sign.c
    src/rfc6979/verify.c
)

# Include directories
target_include_directories(MicroDeterministicECDSA PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Add installation targets
install(TARGETS MicroDeterministicECDSA DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
