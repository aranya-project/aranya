cmake_minimum_required(VERSION 3.11)
project(capi-ctest LANGUAGES C)

# --- Custom: Copy Rust build artifacts and header for C API tests ---
set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../target/debug")
set(RUST_HEADER_GLOB "${RUST_TARGET_DIR}/build/aranya-client-capi-*/out/aranya-client.h")
file(GLOB ARANYA_HEADER_PATH RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" ${RUST_HEADER_GLOB})
set(CTEST_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(CTEST_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(CTEST_EXEC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/exec")

# --- Custom: Build Rust C API and Daemon ---
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

# --- Header generation/copy ---
# Prefer to generate the header with cbindgen if available; otherwise copy
# the generated header from the Rust build output. Both variants depend on
# the Rust crate build to ensure the generated file exists.
find_program(CBINDGEN_EXECUTABLE cbindgen)
if(NOT CBINDGEN_EXECUTABLE)
    message(WARNING "cbindgen not found in PATH. Header generation target will fall back to copying the generated header from the Rust build output. Install cbindgen (https://github.com/cbindgen/cbindgen) for automatic header generation.")
endif()

if(CBINDGEN_EXECUTABLE)
    add_custom_command(
        OUTPUT ${CTEST_INCLUDE_DIR}/aranya-client.h
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CTEST_INCLUDE_DIR}
        COMMAND ${CMAKE_COMMAND} -E env RUSTC_BOOTSTRAP=1 _CBINDGEN_IS_RUNNING=1 ${CBINDGEN_EXECUTABLE} --config ${CMAKE_CURRENT_SOURCE_DIR}/../cbindgen.toml --crate aranya-client-capi --output ${CTEST_INCLUDE_DIR}/aranya-client.h
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/..
        COMMENT "Generating aranya-client.h with cbindgen (RUSTC_BOOTSTRAP=1, _CBINDGEN_IS_RUNNING=1)"
        VERBATIM
        DEPENDS build_aranya_client_capi
    )
else()
    add_custom_command(
        OUTPUT ${CTEST_INCLUDE_DIR}/aranya-client.h
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CTEST_INCLUDE_DIR}
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${RUST_HEADER_GLOB} ${CTEST_INCLUDE_DIR}/aranya-client.h
        COMMENT "Copying generated aranya-client.h from Rust build output"
        DEPENDS build_aranya_client_capi
    )
endif()

# Logical target for header generation
add_custom_target(generate_aranya_header
    DEPENDS ${CTEST_INCLUDE_DIR}/aranya-client.h
)
add_dependencies(generate_aranya_header build_aranya_client_capi)

# Copy library and daemon artifacts into ctest/ if they exist. Use guarded
# shell-copy commands so missing files won't cause the build to fail. The
# copy target depends on the Rust build targets and header generation so
# those are executed first; the copy commands themselves check existence at
# runtime and skip when the source is not present.
set(ARANYA_LIB1 "${RUST_TARGET_DIR}/libaranya_client_capi.dylib")
set(ARANYA_LIB_SO "${RUST_TARGET_DIR}/libaranya_client.so")
set(ARANYA_DAEMON_BIN "${RUST_TARGET_DIR}/aranya-daemon")

add_custom_target(copy_aranya_artifacts ALL
    DEPENDS generate_aranya_header build_aranya_client_capi build_aranya_daemon
    COMMENT "Staging aranya C API header, libs and daemon into ctest/"
)

add_custom_command(TARGET copy_aranya_artifacts POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CTEST_LIB_DIR}
    # Try to copy header from crate output if present (fallback when cbindgen
    # wrote to `crates/aranya-client-capi/output/aranya-client.h`).
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CTEST_INCLUDE_DIR}
    COMMAND /bin/sh -c '[ -f "${CMAKE_CURRENT_SOURCE_DIR}/../output/aranya-client.h" ] && cp -p "${CMAKE_CURRENT_SOURCE_DIR}/../output/aranya-client.h" "${CTEST_INCLUDE_DIR}/aranya-client.h" || echo "Skipping header copy: output/aranya-client.h not found"'
    COMMAND /bin/sh -c '[ -f "${ARANYA_LIB1}" ] && cp -p "${ARANYA_LIB1}" "${CTEST_LIB_DIR}/libaranya_client_capi.dylib" || echo "Skipping copy: ${ARANYA_LIB1} not found or copy failed"'
    COMMAND /bin/sh -c '[ -f "${ARANYA_LIB_SO}" ] && cp -p "${ARANYA_LIB_SO}" "${CTEST_LIB_DIR}/libaranya_client.so" || echo "Skipping copy: ${ARANYA_LIB_SO} not found or copy failed"'
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CTEST_EXEC_DIR}
    COMMAND /bin/sh -c '[ -f "${ARANYA_DAEMON_BIN}" ] && ( cp -p "${ARANYA_DAEMON_BIN}" "${CTEST_EXEC_DIR}/aranya-daemon" && chmod +x "${CTEST_EXEC_DIR}/aranya-daemon" ) || echo "Skipping copy: ${ARANYA_DAEMON_BIN} not found or copy failed"'
)

# Enforce building only under ctest/build
get_filename_component(_build_dir "${CMAKE_BINARY_DIR}" REALPATH)
get_filename_component(_ctest_dir "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
string(FIND "${_build_dir}" "${_ctest_dir}/build" _found_build)
if(NOT (_found_build EQUAL 0 OR _found_build GREATER 0))
    message(FATAL_ERROR "\n\nERROR: You must run cmake from a build directory under: ${_ctest_dir}/build\n\nCurrent build dir: ${_build_dir}\n\nPlease create and use a build directory inside ctest/build.\n\nExample:\n  mkdir -p ${_ctest_dir}/build && cd ${_ctest_dir}/build && cmake ..\n")
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_VERBOSE_MAKEFILE ON)

enable_testing()

# Where the generated C header should be copied for tests.
set(TEST_HEADER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(TEST_INCLUDE_DIRS
    ${TEST_HEADER_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Ensure header exists. If missing, do NOT fail configure; warn and
# rely on the build step to run `cargo build` and copy the header.
set(EXPECTED_HEADER "${TEST_HEADER_DIR}/aranya-client.h")
if(NOT EXISTS "${EXPECTED_HEADER}")
    message(WARNING "Expected C header not found: ${EXPECTED_HEADER}\nThe header will be generated and copied when you run 'cmake --build .' (the build runs cargo and the copy targets).\nIf you prefer to generate it manually, run: 'cargo build -p aranya-client-capi --features afc,experimental,preview' and copy the generated header to ${TEST_HEADER_DIR}/")
endif()

# Path to Rust build artifacts (adjust to release if you prefer)
# ctest lives at crates/aranya-client-capi/ctest, so go up three levels
# to reach the workspace root `target/debug` directory.
set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../target/debug")

# Allow using a local lib copy under ctest/lib/ (useful when the generated
# header and a copy of the dylib are placed inside the ctest dir for tests).
set(LOCAL_LIB_DYLIB1 "${CMAKE_CURRENT_SOURCE_DIR}/lib/libaranya_client.dylib")
set(LOCAL_LIB_DYLIB2 "${CMAKE_CURRENT_SOURCE_DIR}/lib/libaranya_client_capi.dylib")


# Try common library names produced by the crate build.

set(ARANYA_LIB_DYLIB1 "${RUST_TARGET_DIR}/libaranya_client.dylib")
set(ARANYA_LIB_DYLIB2 "${RUST_TARGET_DIR}/libaranya_client_capi.dylib")
set(ARANYA_LIB_A     "${RUST_TARGET_DIR}/libaranya_client.a")

set(ARANYA_LIB "")
# Prefer a local copy inside ctest/lib/ if present
if(EXISTS "${LOCAL_LIB_DYLIB2}")
    set(ARANYA_LIB "${LOCAL_LIB_DYLIB2}")
elseif(EXISTS "${LOCAL_LIB_DYLIB1}")
    set(ARANYA_LIB "${LOCAL_LIB_DYLIB1}")
elseif(EXISTS "${ARANYA_LIB_DYLIB2}")
    set(ARANYA_LIB "${ARANYA_LIB_DYLIB2}")
elseif(EXISTS "${ARANYA_LIB_DYLIB1}")
    set(ARANYA_LIB "${ARANYA_LIB_DYLIB1}")
elseif(EXISTS "${ARANYA_LIB_A}")
    set(ARANYA_LIB "${ARANYA_LIB_A}")
else()
    message(WARNING "Rust C API library not found in ${RUST_TARGET_DIR} or ${CMAKE_CURRENT_SOURCE_DIR}/lib. Build the crate first (e.g. `cargo build -p aranya-client-capi --features afc`) or copy the generated dylib into ${CMAKE_CURRENT_SOURCE_DIR}/lib/.")
endif()

# Test: TestSimple
add_executable(TestSimple test_simple.c)
target_include_directories(TestSimple PRIVATE ${TEST_INCLUDE_DIRS})
# opt into preview APIs required by generated header
target_compile_definitions(TestSimple PRIVATE ENABLE_ARANYA_PREVIEW=1)

# Ensure test executables are built after artifacts (header/lib/daemon) are staged
add_dependencies(TestSimple copy_aranya_artifacts)

if(ARANYA_LIB)
    target_link_libraries(TestSimple PRIVATE "${ARANYA_LIB}")
    if(NOT WIN32)
        target_link_options(TestSimple PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
    endif()
endif()

# Find the aranya-daemon executable
set(DAEMON_LOCAL "${CMAKE_CURRENT_SOURCE_DIR}/exec/aranya-daemon")
set(DAEMON_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release/aranya-daemon")
set(ARANYA_DAEMON "")

if(EXISTS "${DAEMON_LOCAL}")
    set(ARANYA_DAEMON "${DAEMON_LOCAL}")
    message(STATUS "Found aranya-daemon at ${DAEMON_LOCAL}")
elseif(EXISTS "${DAEMON_RELEASE}")
    set(ARANYA_DAEMON "${DAEMON_RELEASE}")
    message(STATUS "Found aranya-daemon at ${DAEMON_RELEASE}")
else()
    message(WARNING "aranya-daemon not found at ${DAEMON_LOCAL} or ${DAEMON_RELEASE}. TestSimple will be skipped.")
endif()

# Register TestSimple test only if daemon was found
if(ARANYA_DAEMON)
    add_test(NAME TestSimple COMMAND TestSimple "${ARANYA_DAEMON}")
    set_property(TEST TestSimple APPEND PROPERTY ENVIRONMENT
    "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
)
else()
    message(STATUS "Skipping TestSimple registration (daemon not found)")
endif()

# Optional AFC test executable if the source exists
# NOTE: TestAfc is currently disabled due to API incompatibilities in the generated C header.
# The test uses functions and types that are not currently exposed by the C API.
# if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_afc.c")
#     add_executable(TestAfc test_afc.c)
#     target_include_directories(TestAfc PRIVATE ${TEST_INCLUDE_DIRS})
#     target_compile_definitions(TestAfc PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_AFC=1 ENABLE_ARANYA_EXPERIMENTAL=1)
# 
#     if(ARANYA_LIB)
#         target_link_libraries(TestAfc PRIVATE "${ARANYA_LIB}")
#         if(NOT WIN32)
#             target_link_options(TestAfc PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
#         endif()
#     endif()
# 
#     add_dependencies(TestAfc copy_aranya_artifacts)
# 
#     # Register TestAfc test with daemon path if daemon is found
#     if(ARANYA_DAEMON)
#         add_test(NAME TestAfc COMMAND TestAfc "${ARANYA_DAEMON}")
#     else()
#         add_test(NAME TestAfc COMMAND TestAfc)
#     endif()
#     
#     set_property(TEST TestAfc PROPERTY ENVIRONMENT
#     "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
#     )
# 
#     set_property(TEST TestAfc PROPERTY TIMEOUT 60)
# endif()

# Optional Team/Role test executable if the source exists
# NOTE: TestTeam is currently disabled due to API incompatibilities in the generated C header.
# The test assumes role enums and constants that are not exposed in the current C API.
# if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_team.c")
#     add_executable(TestTeam test_team.c)
#     target_include_directories(TestTeam PRIVATE ${TEST_INCLUDE_DIRS})
#     target_compile_definitions(TestTeam PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_EXPERIMENTAL=1)
# 
#     if(ARANYA_LIB)
#         target_link_libraries(TestTeam PRIVATE "${ARANYA_LIB}")
#         if(NOT WIN32)
#             target_link_options(TestTeam PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
#         endif()
#     endif()
# 
#     # Register TestTeam test with daemon path if daemon is found
#     if(ARANYA_DAEMON)
#         add_test(NAME TestTeam COMMAND TestTeam "${ARANYA_DAEMON}")
#     else()
#         add_test(NAME TestTeam COMMAND TestTeam)
#     endif()
#     
#     set_property(TEST TestTeam PROPERTY ENVIRONMENT
#     "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
#     )
#     add_dependencies(TestTeam copy_aranya_artifacts)
# endif()

# Optional Sync test executable if the source exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_sync.c")
    add_executable(TestSync test_sync.c)
    target_include_directories(TestSync PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_definitions(TestSync PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_EXPERIMENTAL=1)

    if(ARANYA_LIB)
        target_link_libraries(TestSync PRIVATE "${ARANYA_LIB}")
        if(NOT WIN32)
            target_link_options(TestSync PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
        endif()
    endif()

    add_test(NAME TestSync COMMAND TestSync "${ARANYA_DAEMON}")

    set_property(TEST TestSync PROPERTY ENVIRONMENT
    "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
    )
    add_dependencies(TestSync copy_aranya_artifacts)
endif()

# Optional DataTypes test executable if the source exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_datatypes.c")
    add_executable(TestDataTypes test_datatypes.c)
    target_include_directories(TestDataTypes PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_definitions(TestDataTypes PRIVATE ENABLE_ARANYA_PREVIEW=1)

    if(ARANYA_LIB)
        target_link_libraries(TestDataTypes PRIVATE "${ARANYA_LIB}")
        if(NOT WIN32)
            target_link_options(TestDataTypes PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
        endif()
    endif()

    add_test(NAME TestDataTypes COMMAND TestDataTypes)

    set_property(TEST TestDataTypes PROPERTY ENVIRONMENT
    "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
    )
    add_dependencies(TestDataTypes copy_aranya_artifacts)
endif()

# Optional Client test executable if the source exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_client.c")
    add_executable(TestClient test_client.c)
    target_include_directories(TestClient PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_definitions(TestClient PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_EXPERIMENTAL=1)

    if(ARANYA_LIB)
        target_link_libraries(TestClient PRIVATE "${ARANYA_LIB}")
        if(NOT WIN32)
            target_link_options(TestClient PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
        endif()
    endif()

    # Register TestClient test with daemon path if daemon is found
    if(ARANYA_DAEMON)
        add_test(NAME TestClient COMMAND TestClient "${ARANYA_DAEMON}")
    else()
        add_test(NAME TestClient COMMAND TestClient)
    endif()
    
    set_property(TEST TestClient PROPERTY ENVIRONMENT
    "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
    )
    add_dependencies(TestClient copy_aranya_artifacts)
endif()

# Optional Query test executable if the source exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_query.c")
    add_executable(TestQuery test_query.c)
    target_include_directories(TestQuery PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_definitions(TestQuery PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_EXPERIMENTAL=1)

    if(ARANYA_LIB)
        target_link_libraries(TestQuery PRIVATE "${ARANYA_LIB}")
        if(NOT WIN32)
            target_link_options(TestQuery PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
        endif()
    endif()

    # Register TestQuery test with daemon path if daemon is found
    if(ARANYA_DAEMON)
        add_test(NAME TestQuery COMMAND TestQuery "${ARANYA_DAEMON}")
    else()
        add_test(NAME TestQuery COMMAND TestQuery)
    endif()
    
    set_property(TEST TestQuery PROPERTY ENVIRONMENT
    "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
)
    add_dependencies(TestQuery copy_aranya_artifacts)
endif()
