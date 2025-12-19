cmake_minimum_required(VERSION 3.11)
project(capi-ctest LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Enforce building only under ctest/build
get_filename_component(_build_dir "${CMAKE_BINARY_DIR}" REALPATH)
get_filename_component(_ctest_dir "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
string(FIND "${_build_dir}" "${_ctest_dir}/build" _found_build)
if(NOT (_found_build EQUAL 0 OR _found_build GREATER 0))
    message(FATAL_ERROR "\n\nERROR: You must run cmake from a build directory under: ${_ctest_dir}/build\n\nCurrent build dir: ${_build_dir}\n\nPlease create and use a build directory inside ctest/build.\n\nExample:\n  mkdir -p ${_ctest_dir}/build && cd ${_ctest_dir}/build && cmake ..\n")
endif()

# --- Paths ---
set(RUST_TARGET_DIR "$ENV{ARANYA_TARGET_DIR}")
if(NOT RUST_TARGET_DIR)
    set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../target/release")
endif()
set(CAPI_HEADER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../output")
set(CTEST_SOURCE_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")

# --- Build Rust C API and Daemon ---
add_custom_command(
    OUTPUT ${RUST_TARGET_DIR}/libaranya_client_capi.dylib ${RUST_TARGET_DIR}/libaranya_client_capi.so
    COMMAND cargo make build-capi
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../..
    COMMENT "Building aranya-client-capi with cargo make"
)

add_custom_target(build_aranya_client_capi
    DEPENDS ${RUST_TARGET_DIR}/libaranya_client_capi.dylib ${RUST_TARGET_DIR}/libaranya_client_capi.so
)

add_custom_target(build_aranya_daemon ALL
    COMMAND cargo make build-experimental
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../../..
    COMMENT "Building aranya-daemon with cargo make"
)

# --- Library Detection ---
# Point directly to Rust target directory instead of copying
set(ARANYA_LIB "")
if(EXISTS "${RUST_TARGET_DIR}/libaranya_client_capi.dylib")
    set(ARANYA_LIB "${RUST_TARGET_DIR}/libaranya_client_capi.dylib")
elseif(EXISTS "${RUST_TARGET_DIR}/libaranya_client_capi.so")
    set(ARANYA_LIB "${RUST_TARGET_DIR}/libaranya_client_capi.so")
else()
    # Library doesn't exist yet at configure time, will be built later
    # Try to use the most likely name for the platform
    if(APPLE)
        set(ARANYA_LIB "${RUST_TARGET_DIR}/libaranya_client_capi.dylib")
    else()
        set(ARANYA_LIB "${RUST_TARGET_DIR}/libaranya_client_capi.so")
    endif()
endif()

message(STATUS "Using Aranya library: ${ARANYA_LIB}")

# --- Daemon Detection ---
# Point directly to Rust target directory instead of copying
set(ARANYA_DAEMON "${RUST_TARGET_DIR}/aranya-daemon")

# --- Testing Setup ---
enable_testing()

# --- Helper function for test executables ---
function(add_capi_test TEST_NAME SOURCE_FILE)
    cmake_parse_arguments(ARG "" "DAEMON_NAMES" "" ${ARGN})
    
    add_executable(${TEST_NAME} ${SOURCE_FILE})
    target_include_directories(${TEST_NAME} PRIVATE ${CAPI_HEADER_DIR} ${CTEST_SOURCE_INCLUDE_DIR})
    target_compile_definitions(${TEST_NAME} PRIVATE)
    
    # Ensure library and daemon are built before compiling
    add_dependencies(${TEST_NAME} build_aranya_client_capi)
    add_dependencies(${TEST_NAME} build_aranya_daemon)
    
    if(ARANYA_LIB)
        target_link_libraries(${TEST_NAME} PRIVATE "${ARANYA_LIB}")
        if(NOT WIN32)
            target_link_options(${TEST_NAME} PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
        endif()
    endif()
    
    # Always use wrapper script for uniform test execution
    add_test(NAME ${TEST_NAME} 
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/execute_test.sh 
                ${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME} "${ARANYA_DAEMON}" "${ARG_DAEMON_NAMES}")
    
    set_property(TEST ${TEST_NAME} PROPERTY ENVIRONMENT
        "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}")
endfunction()

# --- Test Executables ---
add_capi_test(TestOnboarding test_onboarding.c DAEMON_NAMES "owner,member")
add_capi_test(TestSimple test_simple.c)


