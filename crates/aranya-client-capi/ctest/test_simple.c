#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "aranya-client.h"

#define TRY(err)                                                               \
    do {                                                                       \
        if (err != ARANYA_ERROR_SUCCESS)                                       \
            return EXIT_FAILURE;                                               \
    } while (0);

static pid_t spawn_daemon(const char *path) {
    pid_t pid = fork();
    if (pid != 0) {
        return pid;
    }

    char *env[] = {
        "ARANYA_DAEMON=debug",
        NULL,
    };
    // Show that we can run the daemon by path passed to the test.
    int ret = execle(path, path, "--help", NULL, env);
    fprintf(stderr, "unexpected return %d", ret);
    abort();
}

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: `%s <daemon>`\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Show that we can use the client library.
    AranyaExtError ext;
    TRY(aranya_ext_error_init(&ext));
    TRY(aranya_ext_error_cleanup(&ext));

    spawn_daemon(argv[1]);
    int status;
    wait(&status);
    bool success = WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS;

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
