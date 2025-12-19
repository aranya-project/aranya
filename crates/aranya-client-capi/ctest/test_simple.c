#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* include the generated C API header (CMake should add the include dir) */
#include "aranya-client.h"
#include "utils.h"

/* Minimal test harness that runs a few small checks and reports results to
   stdout. CTest will see the executable as a single test; the harness runs
   multiple subtests and fails the whole test if any subtest fails. */

/* Test: aranya_error_to_str returns a non-empty string for success code. */
static int test_error_to_str_success(void) {
    const char *s = aranya_error_to_str(ARANYA_ERROR_SUCCESS);
    if (s == NULL) {
        return 0;
    }
    return s[0] != '\0';
}

/* Test: aranya_error_to_str returns a non-empty string for an invalid code. */
static int test_error_to_str_invalid(void) {
    const unsigned bogus = 0xDEADBEEFu;
    const char *s = aranya_error_to_str(bogus);
    if (s == NULL) {
        return 0;
    }
    return s[0] != '\0';
}

int main(void) {
    printf("Running aranya-client-capi simple subtests\n");

    if (!test_error_to_str_success()) {
        fprintf(stderr, "FAILED: error_to_str(success)\n");
        return EXIT_FAILURE;
    }
    if (!test_error_to_str_invalid()) {
        fprintf(stderr, "FAILED: error_to_str(invalid)\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
