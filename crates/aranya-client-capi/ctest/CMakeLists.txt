cmake_minimum_required(VERSION 3.11)

project(capi-ctest LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_VERBOSE_MAKEFILE ON)

if("${CMAKE_C_COMPILER_ID}" MATCHES "Clang")
	set(CLANG TRUE)
endif()

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
    set(APPLE TRUE)
endif()

if("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    set(WINDOWS TRUE)
endif()

# Test builds run with extra runtime checks.
add_compile_options(
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
)
add_link_options(
    -fsanitize=address,undefined
    -fno-omit-frame-pointer
)
if(CLANG)
    add_compile_options(
        -fsanitize=nullability,local-bounds
    )
    add_link_options(
        -fsanitize=nullability,local-bounds
    )
endif()

# macOS always defines _FORTIFY_SOURCE, so avoid re-defining
# the macro by undefining it first.
if(APPLE)
    add_compile_options(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
else()
    add_compile_definitions(_FORTIFY_SOURCE=2)
endif()

add_compile_options(
    -O2
    -Wall -Wextra -Werror
    -Wswitch
    -Wpointer-arith -Wmissing-prototypes
    -Warray-bounds -Werror=array-bounds
    -Wunused-result
	-march=native
    -pedantic

	# These are because of cbindgen.
	-Wno-gnu-anonymous-struct
	-Wno-nested-anon-types
)

if(NOT WINDOWS)
    add_compile_options(
        -fPIE
        -Wno-address-of-packed-member
        -Wno-gnu-auto-type
        -Wno-gnu-case-range
        -Wno-gnu-statement-expression
        -Wno-gnu-variable-sized-type-not-at-end
        -Wno-gnu-zero-variadic-macro-arguments
        -Wno-nullability-extension
        -Wno-c11-extensions
        -Wno-c99-extensions
    )
	if(CLANG)
		add_compile_options(
			-Wtype-safety
		)
	endif()
else()
    add_compile_options(
        -Wtype-limits
    )
endif()

# Apple and Windows system linkers do not recognize these options.
if(NOT APPLE AND NOT WINDOWS)
    add_link_options(
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,defs
        -Wl,-z,noexecstack
    )
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

enable_testing()

#add_executable(TestSimple test_simple.c)
#target_link_libraries(TestSimple PRIVATE Aranya::Client)
#add_test(NAME TestSimple COMMAND TestSimple $<TARGET_FILE:Aranya::Daemon>)

#add_executable(TestOnboarding test_onboarding.c)
#target_link_libraries(TestOnboarding PRIVATE Aranya::Client)
#add_test(NAME TestOnboarding COMMAND TestOnboarding $<TARGET_FILE:Aranya::Daemon>)

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
    if("${TEST_NAME}" STREQUAL "TestOnboarding")
        add_test(NAME ${TEST_NAME} 
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/execute_test.sh 
                    ${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME} "${ARANYA_DAEMON}" "${ARG_DAEMON_NAMES}")
    else()
        add_test(NAME ${TEST_NAME} 
            COMMAND ${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME} "${ARANYA_DAEMON}")
    endif()
    
    set_property(TEST ${TEST_NAME} PROPERTY ENVIRONMENT
        "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}")
endfunction()

# --- Test Executables ---
add_capi_test(TestOnboarding test_onboarding.c DAEMON_NAMES "owner,member")
add_capi_test(TestSimple test_simple.c)
