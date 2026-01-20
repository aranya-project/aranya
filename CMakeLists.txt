cmake_minimum_required(VERSION 3.24...3.31)

project(aranya-client LANGUAGES C)

# Tests are built by default when the project is used directly. If the project
# is used as a dependency (like with `FetchContent`), you must manually enable
# the tests if desired.
option(ARANYA_BUILD_TESTS "Controls whether to build Aranya's test suite." ${PROJECT_IS_TOP_LEVEL})

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(ARANYA_BUILD_TESTS)
    include(CTest)
endif()
include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.6.0
)
# Set any global configuration variables such as `Rust_TOOLCHAIN` before this line!
FetchContent_MakeAvailable(Corrosion)

add_subdirectory(crates/aranya-client-capi)
