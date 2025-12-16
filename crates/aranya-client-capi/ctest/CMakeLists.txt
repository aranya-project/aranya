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
set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../target/debug")
set(CTEST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(CTEST_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(CTEST_EXEC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/exec")

# --- Build Rust C API and Daemon ---
add_custom_target(build_aranya_client_capi ALL
    COMMAND cargo build -p aranya-client-capi --features afc,experimental,preview
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../..
    COMMENT "Building aranya-client-capi with cargo"
)

add_custom_target(build_aranya_daemon ALL
    COMMAND cargo build -p aranya-daemon --features afc,experimental,preview
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/../..
    COMMENT "Building aranya-daemon with cargo"
)

# --- Header Generation ---
find_program(CBINDGEN_EXECUTABLE cbindgen)
if(NOT CBINDGEN_EXECUTABLE)
    message(WARNING "cbindgen not found in PATH. Will copy generated header from Rust build output instead.")
endif()

if(CBINDGEN_EXECUTABLE)
    add_custom_command(
        OUTPUT ${CTEST_INCLUDE_DIR}/aranya-client.h
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CTEST_INCLUDE_DIR}
        COMMAND ${CMAKE_COMMAND} -E env RUSTC_BOOTSTRAP=1 _CBINDGEN_IS_RUNNING=1 
                ${CBINDGEN_EXECUTABLE} --config ${CMAKE_CURRENT_SOURCE_DIR}/../cbindgen.toml 
                --crate aranya-client-capi --output ${CTEST_INCLUDE_DIR}/aranya-client.h
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
        COMMENT "Generating aranya-client.h with cbindgen"
        VERBATIM
        DEPENDS build_aranya_client_capi
    )
else()
    set(RUST_HEADER_GLOB "${RUST_TARGET_DIR}/build/aranya-client-capi-*/out/aranya-client.h")
    add_custom_command(
        OUTPUT ${CTEST_INCLUDE_DIR}/aranya-client.h
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CTEST_INCLUDE_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RUST_HEADER_GLOB} ${CTEST_INCLUDE_DIR}/aranya-client.h
        COMMENT "Copying generated aranya-client.h from Rust build output"
        DEPENDS build_aranya_client_capi
    )
endif()

add_custom_target(generate_aranya_header DEPENDS ${CTEST_INCLUDE_DIR}/aranya-client.h)
add_dependencies(generate_aranya_header build_aranya_client_capi)

# --- Copy Artifacts ---
add_custom_target(copy_aranya_artifacts ALL
    DEPENDS generate_aranya_header build_aranya_client_capi build_aranya_daemon
    COMMENT "Staging aranya C API artifacts into ctest/"
)

add_custom_command(TARGET copy_aranya_artifacts POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CTEST_LIB_DIR} ${CTEST_EXEC_DIR}
    COMMAND /bin/sh -c '[ -f "${RUST_TARGET_DIR}/libaranya_client_capi.dylib" ] && cp -p "${RUST_TARGET_DIR}/libaranya_client_capi.dylib" "${CTEST_LIB_DIR}/" || true'
    COMMAND /bin/sh -c '[ -f "${RUST_TARGET_DIR}/libaranya_client.so" ] && cp -p "${RUST_TARGET_DIR}/libaranya_client.so" "${CTEST_LIB_DIR}/" || true'
    COMMAND /bin/sh -c '[ -f "${RUST_TARGET_DIR}/aranya-daemon" ] && ( cp -p "${RUST_TARGET_DIR}/aranya-daemon" "${CTEST_EXEC_DIR}/" && chmod +x "${CTEST_EXEC_DIR}/aranya-daemon" ) || true'
)

# --- Library Detection ---
# Note: Library may not exist at configure time but will be built/copied during build phase
set(ARANYA_LIB "")
if(EXISTS "${CTEST_LIB_DIR}/libaranya_client_capi.dylib")
    set(ARANYA_LIB "${CTEST_LIB_DIR}/libaranya_client_capi.dylib")
elseif(EXISTS "${RUST_TARGET_DIR}/libaranya_client_capi.dylib")
    set(ARANYA_LIB "${RUST_TARGET_DIR}/libaranya_client_capi.dylib")
elseif(EXISTS "${RUST_TARGET_DIR}/libaranya_client.so")
    set(ARANYA_LIB "${RUST_TARGET_DIR}/libaranya_client.so")
endif()

# --- Daemon Detection ---
# Note: Daemon will be copied to exec/ during build phase by copy_aranya_artifacts target
set(ARANYA_DAEMON "${CTEST_EXEC_DIR}/aranya-daemon")

# --- Testing Setup ---
enable_testing()

# Global test fixture to clean up test directories before running tests
add_test(NAME cleanup_tmp_onboarding COMMAND ${CMAKE_COMMAND} -E rm -rf 
    /tmp/onboarding-run-owner /tmp/onboarding-run-member)
set_property(TEST cleanup_tmp_onboarding PROPERTY FIXTURES_SETUP global_test_fixture)

# --- Helper function for test executables ---
function(add_capi_test TEST_NAME SOURCE_FILE)
    cmake_parse_arguments(ARG "REQUIRES_DAEMON;USE_WRAPPER" "" "" ${ARGN})
    
    add_executable(${TEST_NAME} ${SOURCE_FILE})
    target_include_directories(${TEST_NAME} PRIVATE ${CTEST_INCLUDE_DIR})
    target_compile_definitions(${TEST_NAME} PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_EXPERIMENTAL=1)
    
    if(ARANYA_LIB)
        target_link_libraries(${TEST_NAME} PRIVATE "${ARANYA_LIB}")
        if(NOT WIN32)
            target_link_options(${TEST_NAME} PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
        endif()
    endif()
    
    add_dependencies(${TEST_NAME} copy_aranya_artifacts)
    
    if(ARG_USE_WRAPPER AND ARANYA_DAEMON)
        add_test(NAME ${TEST_NAME} 
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run_test_with_cleanup.sh 
                    ${CMAKE_CURRENT_BINARY_DIR}/${TEST_NAME} "${ARANYA_DAEMON}")
    elseif(ARG_REQUIRES_DAEMON AND ARANYA_DAEMON)
        add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME} "${ARANYA_DAEMON}")
    else()
        add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    endif()
    
    set_property(TEST ${TEST_NAME} PROPERTY ENVIRONMENT
        "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}")
    
    set_property(TEST ${TEST_NAME} PROPERTY FIXTURES_REQUIRED global_test_fixture)
endfunction()

# --- Test Executables ---
add_capi_test(TestOnboarding test_onboarding.c USE_WRAPPER)
add_capi_test(TestSimple test_simple.c USE_WRAPPER)
