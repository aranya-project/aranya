#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#ifndef ENABLE_ARANYA_PREVIEW
# define ENABLE_ARANYA_PREVIEW 1
#endif

/* include the generated C API header (CMake should add the include dir) */
#include "aranya-client.h"
#include "utils.h"

/* Minimal test harness that runs a few small checks and reports results to stdout.
   CTest will see the executable as a single test; the harness runs multiple
   subtests and fails the whole test if any subtest fails. */

/* Test: aranya_error_to_str returns a non-empty string for success code. */
static int test_error_to_str_success(void) {
#ifdef ARANYA_ERROR_SUCCESS
    unsigned code = (unsigned)ARANYA_ERROR_SUCCESS;
#else
    unsigned code = 0u;
#endif
    const char *s = aranya_error_to_str(code);
    return s != NULL && s[0] != '\0';
}

/* Test: aranya_error_to_str returns a non-empty string for an invalid code. */
static int test_error_to_str_invalid(void) {
    const unsigned bogus = 0xDEADBEEFu;
    const char *s = aranya_error_to_str(bogus);
    return s != NULL && s[0] != '\0';
}

int main(void) {
    printf("Running aranya-client-capi simple subtests\n");

    if (!test_error_to_str_success()) {
        printf("FAILED: error_to_str(success)\n");
        return EXIT_FAILURE;
    }
    if (!test_error_to_str_invalid()) {
        printf("FAILED: error_to_str(invalid)\n");
        return EXIT_FAILURE;
    }

    printf("ALL SUBTESTS PASSED\n");
    return EXIT_SUCCESS;
}
