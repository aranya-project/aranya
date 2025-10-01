#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: `%s <daemon>`\n", argv[0]);
        return EXIT_FAILURE;
    }

    spawn_daemon(argv[1]);
    wait(NULL);

    return EXIT_SUCCESS;
}
