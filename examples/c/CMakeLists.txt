cmake_minimum_required(VERSION 3.15)

project(c-example-application LANGUAGES C)

set(CMAKE_VERBOSE_MAKEFILE ON)

if("${CMAKE_C_COMPILER_ID}" MATCHES "Clang")
    set(CLANG TRUE)
elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
    set(GCC TRUE)
endif()

if(NOT WIN32)
    set(sanitize address,undefined)
    if(CLANG)
        set(sanitize "${sanitize},nullability,local-bounds")
    endif()
    add_compile_options("-fsanitize=${sanitize}" -fno-omit-frame-pointer)
    add_link_options("-fsanitize=${sanitize}" -fno-omit-frame-pointer)
endif()

add_compile_options(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2)

add_compile_options(
    -O2
    -Wall -Wextra -Werror -pedantic
    -Wpointer-arith
    -Wmissing-prototypes
    -Wno-gnu-zero-variadic-macro-arguments
)

add_compile_options(-DENABLE_AFC)
add_compile_options(-DENABLE_ARANYA_PREVIEW)
add_compile_options(-DENABLE_AQC)
add_compile_options(-DENABLE_ARANYA_EXPERIMENTAL)

# Apple and Windows system linkers do not recognize these options.
if(NOT APPLE AND NOT WIN32)
    add_link_options(
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,defs
        -Wl,-z,noexecstack
    )
endif()

enable_testing()

find_package(Aranya REQUIRED)

add_test(NAME TestSetup COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/work_dir)
add_test(NAME TestCleanup COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/work_dir)

function(do_test NAME)
    cmake_parse_arguments(ARG "" "" "SOURCES;LIBRARIES" ${ARGN})
    add_executable(${NAME} ${ARG_SOURCES})
    target_link_libraries(${NAME} Aranya::Aranya ${ARG_LIBRARIES})
    add_test(NAME ${NAME} COMMAND ${NAME} ${CMAKE_BINARY_DIR}/work_dir)
    set_tests_properties(${NAME} PROPERTIES
        FIXTURES_REQUIRED ARANYA
        ENVIRONMENT "ASAN_OPTIONS=detect_leaks=0")
endfunction()

do_test(example SOURCES example.c)

set_tests_properties(TestSetup PROPERTIES FIXTURES_SETUP ARANYA)
set_tests_properties(TestCleanup PROPERTIES FIXTURES_CLEANUP ARANYA)
