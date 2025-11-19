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

static pid_t spawn_daemon(const char *path) {
    pid_t pid = fork();
        if (pid != 0) {
        return pid;
    }

    char *env[] = {
        "ARANYA_DAEMON=debug",
        NULL,
    };
    int ret = execle(path, path, "--help", NULL, env);
    fprintf(stderr, "unexpected return %d", ret);
    abort();
}

/* Minimal test harness that runs a few small checks and reports results to stdout.
   CTest will see the executable as a single test; the harness runs multiple
   subtests and fails the whole test if any subtest fails. */

static void report(const char *name, int ok, int *fail_count) {
    printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) (*fail_count)++;
}

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

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: `%s <daemon>`\n", argv[0]);
        return EXIT_FAILURE;
    }

    spawn_daemon(argv[1]);
    wait(NULL);

    int fails = 0;

    printf("Running aranya-client-capi basic subtests\n");

    report("error_to_str(success)", test_error_to_str_success(), &fails);
    report("error_to_str(invalid)", test_error_to_str_invalid(), &fails);

    if (fails == 0) {
        printf("ALL SUBTESTS PASSED\n");
        return EXIT_SUCCESS;
    } else {
        printf("%d SUBTEST(S) FAILED\n", fails);
        return EXIT_FAILURE;
    }
}
