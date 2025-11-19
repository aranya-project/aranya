cmake_minimum_required(VERSION 3.11)
project(capi-ctest LANGUAGES C)

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

# Ensure header exists (fail early with a clear message).
set(EXPECTED_HEADER "${TEST_HEADER_DIR}/aranya-client.h")
if(NOT EXISTS "${EXPECTED_HEADER}")
    message(FATAL_ERROR "Expected C header not found: ${EXPECTED_HEADER}\nBuild the aranya-client-capi crate and copy the generated header to ${TEST_HEADER_DIR}/")
endif()

# Path to Rust build artifacts (adjust to release if you prefer)
set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../target/debug")

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
if(EXISTS "${LOCAL_LIB_DYLIB1}")
    set(ARANYA_LIB "${LOCAL_LIB_DYLIB1}")
elseif(EXISTS "${LOCAL_LIB_DYLIB2}")
    set(ARANYA_LIB "${LOCAL_LIB_DYLIB2}")
elseif(EXISTS "${ARANYA_LIB_DYLIB1}")
    set(ARANYA_LIB "${ARANYA_LIB_DYLIB1}")
elseif(EXISTS "${ARANYA_LIB_DYLIB2}")
    set(ARANYA_LIB "${ARANYA_LIB_DYLIB2}")
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
    add_test(NAME TestSimple COMMAND TestSimple)
    set_tests_properties(TestSimple PROPERTIES
        ENVIRONMENT "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
    )
else()
    message(STATUS "Skipping TestSimple registration (daemon not found)")
endif()

# Optional AFC test executable if the source exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_afc.c")
    add_executable(TestAfc test_afc.c)
    target_include_directories(TestAfc PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_definitions(TestAfc PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_AFC=1 ENABLE_ARANYA_AQC=1 ENABLE_ARANYA_EXPERIMENTAL=1)

    if(ARANYA_LIB)
        target_link_libraries(TestAfc PRIVATE "${ARANYA_LIB}")
        if(NOT WIN32)
            target_link_options(TestAfc PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
        endif()
    endif()

    # Register TestAfc test with daemon path if daemon is found
    if(ARANYA_DAEMON)
        add_test(NAME TestAfc COMMAND TestAfc "${ARANYA_DAEMON}")
    else()
        add_test(NAME TestAfc COMMAND TestAfc)
    endif()
    
    set_tests_properties(TestAfc PROPERTIES
        ENVIRONMENT "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
        TIMEOUT 60
    )
endif()

# Optional Team/Role test executable if the source exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_team.c")
    add_executable(TestTeam test_team.c)
    target_include_directories(TestTeam PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_definitions(TestTeam PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_EXPERIMENTAL=1 ENABLE_ARANYA_AQC=1)

    if(ARANYA_LIB)
        target_link_libraries(TestTeam PRIVATE "${ARANYA_LIB}")
        if(NOT WIN32)
            target_link_options(TestTeam PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
        endif()
    endif()

    # Register TestTeam test with daemon path if daemon is found
    if(ARANYA_DAEMON)
        add_test(NAME TestTeam COMMAND TestTeam "${ARANYA_DAEMON}")
    else()
        add_test(NAME TestTeam COMMAND TestTeam)
    endif()
    
    set_tests_properties(TestTeam PROPERTIES
        ENVIRONMENT "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
    )
endif()

# Optional Sync test executable if the source exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_sync.c")
    add_executable(TestSync test_sync.c)
    target_include_directories(TestSync PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_definitions(TestSync PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_EXPERIMENTAL=1 ENABLE_ARANYA_AQC=1)

    if(ARANYA_LIB)
        target_link_libraries(TestSync PRIVATE "${ARANYA_LIB}")
        if(NOT WIN32)
            target_link_options(TestSync PRIVATE "-Wl,-rpath,${RUST_TARGET_DIR}")
        endif()
    endif()

    add_test(NAME TestSync COMMAND TestSync "${ARANYA_DAEMON}")
    set_tests_properties(TestSync PROPERTIES
        ENVIRONMENT "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
    )
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
    set_tests_properties(TestDataTypes PROPERTIES
        ENVIRONMENT "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
    )
endif()

# Optional Client test executable if the source exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_client.c")
    add_executable(TestClient test_client.c)
    target_include_directories(TestClient PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_definitions(TestClient PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_EXPERIMENTAL=1 ENABLE_ARANYA_AQC=1)

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
    
    set_tests_properties(TestClient PROPERTIES
        ENVIRONMENT "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
    )
endif()

# Optional Query test executable if the source exists
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/test_query.c")
    add_executable(TestQuery test_query.c)
    target_include_directories(TestQuery PRIVATE ${TEST_INCLUDE_DIRS})
    target_compile_definitions(TestQuery PRIVATE ENABLE_ARANYA_PREVIEW=1 ENABLE_ARANYA_EXPERIMENTAL=1 ENABLE_ARANYA_AQC=1)

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
    
    set_tests_properties(TestQuery PROPERTIES
        ENVIRONMENT "DYLD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{DYLD_LIBRARY_PATH};LD_LIBRARY_PATH=${RUST_TARGET_DIR}:$ENV{LD_LIBRARY_PATH}"
    )
endif()
