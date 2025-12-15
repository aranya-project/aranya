cmake_minimum_required(VERSION 3.11)
project(capi-ctest LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

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
    COMMAND /bin/sh -c '[ -f "${CMAKE_CURRENT_SOURCE_DIR}/../output/aranya-client.h" ] && cp -p "${CMAKE_CURRENT_SOURCE_DIR}/../output/aranya-client.h" "${CTEST_INCLUDE_DIR}/aranya-client.h" || true'
    COMMAND /bin/sh -c '[ -f "${RUST_TARGET_DIR}/libaranya_client_capi.dylib" ] && cp -p "${RUST_TARGET_DIR}/libaranya_client_capi.dylib" "${CTEST_LIB_DIR}/" || true'
    COMMAND /bin/sh -c '[ -f "${RUST_TARGET_DIR}/libaranya_client.so" ] && cp -p "${RUST_TARGET_DIR}/libaranya_client.so" "${CTEST_LIB_DIR}/" || true'
    COMMAND /bin/sh -c '[ -f "${RUST_TARGET_DIR}/aranya-daemon" ] && ( cp -p "${RUST_TARGET_DIR}/aranya-daemon" "${CTEST_EXEC_DIR}/" && chmod +x "${CTEST_EXEC_DIR}/aranya-daemon" ) || true'
)

# --- Library Detection ---
set(LOCAL_LIB "${CTEST_LIB_DIR}/libaranya_client_capi.dylib")
set(RUST_LIB_DYLIB "${RUST_TARGET_DIR}/libaranya_client_capi.dylib")
set(RUST_LIB_SO "${RUST_TARGET_DIR}/libaranya_client.so")
set(RUST_LIB_A "${RUST_TARGET_DIR}/libaranya_client.a")

set(ARANYA_LIB "")
if(EXISTS "${LOCAL_LIB}")
    set(ARANYA_LIB "${LOCAL_LIB}")
elseif(EXISTS "${RUST_LIB_DYLIB}")
    set(ARANYA_LIB "${RUST_LIB_DYLIB}")
elseif(EXISTS "${RUST_LIB_SO}")
    set(ARANYA_LIB "${RUST_LIB_SO}")
elseif(EXISTS "${RUST_LIB_A}")
    set(ARANYA_LIB "${RUST_LIB_A}")
else()
    message(WARNING "Rust C API library not found. Build the crate first: cargo build -p aranya-client-capi")
endif()

# --- Daemon Detection ---
set(DAEMON_LOCAL "${CTEST_EXEC_DIR}/aranya-daemon")
set(DAEMON_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release/aranya-daemon")
set(ARANYA_DAEMON "")

if(EXISTS "${DAEMON_LOCAL}")
    set(ARANYA_DAEMON "${DAEMON_LOCAL}")
elseif(EXISTS "${DAEMON_RELEASE}")
    set(ARANYA_DAEMON "${DAEMON_RELEASE}")
else()
    message(WARNING "aranya-daemon not found. Tests requiring daemon will be skipped.")
endif()

# --- Testing Setup ---
enable_testing()

# Global test fixtures for cleanup
add_test(NAME global_cleanup COMMAND ${CMAKE_COMMAND} -E echo "Cleaning test runtime directories...")
set_property(TEST global_cleanup PROPERTY FIXTURES_SETUP global_test_fixture)

add_test(NAME cleanup_run COMMAND ${CMAKE_COMMAND} -E rm -rf run)
set_property(TEST cleanup_run PROPERTY FIXTURES_SETUP global_test_fixture)

add_test(NAME create_run_dirs COMMAND ${CMAKE_COMMAND} -E make_directory run/state run/cache run/logs run/config)
set_property(TEST create_run_dirs PROPERTY FIXTURES_SETUP global_test_fixture)

add_test(NAME cleanup_tmp_team COMMAND ${CMAKE_COMMAND} -E rm -rf 
    /tmp/team-run-owner /tmp/team-run-member /tmp/team-run-device)
set_property(TEST cleanup_tmp_team PROPERTY FIXTURES_SETUP global_test_fixture)

add_test(NAME cleanup_tmp_afc COMMAND ${CMAKE_COMMAND} -E rm -rf 
    /tmp/afc-run-owner /tmp/afc-run-member1 /tmp/afc-run-member2)
set_property(TEST cleanup_tmp_afc PROPERTY FIXTURES_SETUP global_test_fixture)

add_test(NAME create_tmp_afc_dirs COMMAND ${CMAKE_COMMAND} -E make_directory 
    /tmp/afc-run-owner/state /tmp/afc-run-owner/cache /tmp/afc-run-owner/logs /tmp/afc-run-owner/config
    /tmp/afc-run-member1/state /tmp/afc-run-member1/cache /tmp/afc-run-member1/logs /tmp/afc-run-member1/config
    /tmp/afc-run-member2/state /tmp/afc-run-member2/cache /tmp/afc-run-member2/logs /tmp/afc-run-member2/config)
set_property(TEST create_tmp_afc_dirs PROPERTY FIXTURES_SETUP global_test_fixture)

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
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_afc.c")
    add_executable(TestAfc test_afc.c)
    target_include_directories(TestAfc PRIVATE ${CTEST_INCLUDE_DIR})
    target_compile_definitions(TestAfc PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_AFC=1 ENABLE_ARANYA_EXPERIMENTAL=1)
    
    if(ARANYA_LIB)
        target_link_libraries(TestAfc PRIVATE "${ARANYA_LIB}")
        if(NOT WIN32)
            target_link_options(TestAfc PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
        endif()
    endif()
    
    add_dependencies(TestAfc copy_aranya_artifacts)
    
    if(ARANYA_DAEMON)
        add_test(NAME TestAfc COMMAND TestAfc "${ARANYA_DAEMON}")
    endif()
    
    set_property(TEST TestAfc PROPERTY ENVIRONMENT
        "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}")
    set_property(TEST TestAfc PROPERTY FIXTURES_REQUIRED global_test_fixture)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_team.c")
    add_capi_test(TestTeam test_team.c USE_WRAPPER)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_sync.c")
    add_capi_test(TestSync test_sync.c REQUIRES_DAEMON)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_datatypes.c")
    add_capi_test(TestDataTypes test_datatypes.c)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_client.c")
    add_capi_test(TestClient test_client.c REQUIRES_DAEMON)
endif()

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_query.c")
    add_capi_test(TestQuery test_query.c REQUIRES_DAEMON)
endif()

