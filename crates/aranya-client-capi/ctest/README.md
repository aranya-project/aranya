
# Aranya C API CTest Suite

This document describes how to build and run the C API integration tests for Aranya using CTest and the provided test harnesses.

## Prerequisites

Ensure you have built all required libraries and executables:

- `crates/aranya-client-capi/output/aranya-client.h`
- `target/release/libaranya_client_capi.dylib` (macOS) or `target/release/libaranya_client_capi.so` (Linux)
- `target/release/aranya-daemon`

## Running Tests

### Run the Full Test Suite using ctest

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

### Run the Full Test Suite using cargo make

**Run the tests:**
  ```sh
  cargo make ctest
  ```

### Run the Full Test Suite using cargo make with verbose enabled

**Run the tests:**
  ```sh
  cargo make ctest-verbose
  ```

> **Tip:** If CTest reports "No tests were found!!!", ensure your `CMakeLists.txt` contains `enable_testing()` and `add_test(...)` entries, and that you are running from the correct build directory.

## Adding a New Test

### 1. Create the Test File

Create a new `.c` file in `crates/aranya-client-capi/ctest/`:

```c
#include <stdio.h>
#include <stdlib.h>
#include "aranya-client.h"
#include "utils.h"

static int test_my_feature(void) {
    AranyaError err;
    
    // Your test logic here
    // Use CLIENT_EXPECT macro for error handling
    
    return EXIT_SUCCESS;
}

int main(int argc, const char *argv[]) {
    printf("Running my feature test\n");
    
    if (test_my_feature() != EXIT_SUCCESS) {
        fprintf(stderr, "FAILED: test_my_feature\n");
        return EXIT_FAILURE;
    }
    
    return EXIT_SUCCESS;
}
```

### 2. Add Test to CMakeLists.txt

Add your test to the "Test Executables" section in `CMakeLists.txt`:

```cmake
# --- Test Executables ---
add_capi_test(TestOnboarding test_onboarding.c REQUIRES_DAEMON DAEMON_NAMES "owner,member")
add_capi_test(TestSimple test_simple.c)
add_capi_test(TestMyFeature test_my_feature.c)  # Add your test here
```

**Options:**
- `REQUIRES_DAEMON` - Wrap test with daemon lifecycle management
- `DAEMON_NAMES "name1,name2"` - Spawn daemons with specified names (requires `REQUIRES_DAEMON`)

### 3. Test Structure

**Simple test (no daemons):**
```cmake
add_capi_test(TestMyFeature test_my_feature.c)
```
**Test with daemons:**
```cmake
add_capi_test(TestMyFeature test_my_feature.c REQUIRES_DAEMON DAEMON_NAMES "owner,member")
```

When `DAEMON_NAMES` is specified:
- Each daemon runs in `$TMPDIR/<name>/` (e.g., `$TMPDIR/owner/`)
- UDS socket is at `$TMPDIR/<name>/uds.sock`
- Your test receives `$TMPDIR` as argv[1]




