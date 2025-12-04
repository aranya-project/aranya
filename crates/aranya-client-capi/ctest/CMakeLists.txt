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
if(NOT DEFINED ENV{NO_TEST_BUILD})
    # TODO(declan): reenable fsanitize. not sure if the leak is occuring in our code.
    # could be in the memtxp but the stack trace hints to it being a cgo malloc.
    add_compile_options(
        #-fsanitize=address
        -fsanitize=undefined,nullability,local-bounds
        -fno-omit-frame-pointer
    )
    add_link_options(
        #-fsanitize=address
        -fsanitize=undefined,nullability,local-bounds
        -fno-omit-frame-pointer
    )

    # macOS always defines _FORTIFY_SOURCE, so avoid re-defining
    # the macro by undefining it first.
    if(APPLE)
        add_compile_options(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)
    else()
        add_compile_definitions(_FORTIFY_SOURCE=2)
    endif()
endif()

add_compile_options(
    -O2
    -Wall -Wextra -Werror
    -Wswitch
    -Wpointer-arith -Wmissing-prototypes
    -Warray-bounds -Werror=array-bounds
    -Wunused-result
	# TODO(eric): make this conditional. Not all compilers
	# support it for whatever reason.
	#-march=native
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

add_executable(TestSimple test_simple.c)
target_link_libraries(TestSimple PRIVATE Aranya::Client)
add_test(NAME TestSimple COMMAND TestSimple $<TARGET_FILE:Aranya::Daemon>)

# add_test(NAME TestSetup
#     COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/accounts")
# add_test(NAME TestCleanup
#     COMMAND ${CMAKE_COMMAND} -E remove_directory "${CMAKE_BINARY_DIR}/accounts")

# add_executable(TestIntegration test_integration.cpp)
# target_link_libraries(TestIntegration PRIVATE APS Aranya::Aranya)
# add_test(NAME TestIntegration COMMAND TestIntegration "${CMAKE_BINARY_DIR}/accounts")
# set_tests_properties(TestIntegration PROPERTIES
#     FIXTURES_REQUIRED APS ENVIRONMENT "${CERT_ENV_VARS};ARANYA_LOG_BASE_CONFIG=development;ARANYA_LOG_LEVEL=info")

# set_tests_properties(TestSetup PROPERTIES FIXTURES_SETUP APS)
# set_tests_properties(TestCleanup PROPERTIES FIXTURES_CLEANUP APS)
