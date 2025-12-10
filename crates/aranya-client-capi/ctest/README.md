
# Aranya C API CTest Suite

This document describes how to build and run the C API integration tests for Aranya using CTest and the provided test harnesses.

## Prerequisites

Ensure you have built all required libraries and executables:

- `ctest/include/aranya-client.h`
- `ctest/lib/libaranya_client.dylib` (macOS) or `ctest/lib/libaranya_client.so` (Linux)
- `ctest/exec/aranya-daemon`

## Build Instructions

### 1. Build the C API library

Run this from the workspace root:

```sh
cargo build -p aranya-client-capi --features afc,experimental,preview
```

### 2. Build the daemon

Run this from the workspace root:

```sh
cargo build -p aranya-daemon --features afc,experimental,preview
```

## Running Tests

### Run a Single Test Manually

From the `ctest` directory:

```sh
DYLD_LIBRARY_PATH=../../target/debug:$DYLD_LIBRARY_PATH \
  ./build/TestTeam ../../target/debug/aranya-daemon | tee /tmp/TestTeam.run.log
```

### Run the Full Test Suite with CTest

1. **Configure the build directory:**
  ```sh
  cd [workspace_path]/crates/aranya-client-capi/ctest/build
  cmake ..
  ```
2. **Build the tests:**
  ```sh
  make
  ```
3. **Run all tests with verbose output:**
  ```sh
  ctest -V --output-on-failure
  ```

> **Tip:** If CTest reports "No tests were found!!!", ensure your `CMakeLists.txt` contains `enable_testing()` and `add_test(...)` entries, and that you are running from the correct build directory.




