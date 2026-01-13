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

enable_testing()

add_library(utils INTERFACE)
target_include_directories(utils INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/include")

# --- Helper function for test executables ---
function(add_capi_test TEST_NAME SOURCE_FILE)
    cmake_parse_arguments(ARG "" "DAEMON_NAMES" "" ${ARGN})

    add_executable(${TEST_NAME} ${SOURCE_FILE})
    target_link_libraries(${TEST_NAME} PRIVATE Aranya::Client utils)

    # Always use wrapper script for uniform test execution
    add_test(NAME ${TEST_NAME}
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/execute_test.sh
        $<TARGET_FILE:${TEST_NAME}> $<TARGET_FILE:Aranya::Daemon> "${ARG_DAEMON_NAMES}")
endfunction()

# --- Test Executables ---
add_capi_test(TestOnboarding test_onboarding.c DAEMON_NAMES "owner,member")
