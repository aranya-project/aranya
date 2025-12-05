#ifndef ARANYA_CTEST_UTILS_H
#define ARANYA_CTEST_UTILS_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Common constants used by tests
#define ARANYA_TEST_DAEMON_ENV "ARANYA_DAEMON"
#define ARANYA_TEST_DEFAULT_TIMEOUT 30 // seconds

// Path buffers used by tests (size chosen for PATH_MAX portability)
#ifndef ARANYA_PATH_MAX
#define ARANYA_PATH_MAX 4096
#endif

// Global configuration structure that tests can read/modify
struct aranya_test_config {
    // Path to daemon executable used by tests. If empty, tests will try
    // to find daemon in default locations.
    char daemon_path[ARANYA_PATH_MAX];

    // Optional additional library search path (used to set env vars when launching tests)
    char lib_search_path[ARANYA_PATH_MAX];

    // Per-test timeout in seconds for long-running operations
    unsigned int timeout_seconds;

    // Verbosity flag for tests to print extra diagnostics
    bool verbose;
};

// Extern global config instance (defined in one test translation unit or provided by test runner)
extern struct aranya_test_config g_aranya_test_config;

// Client helper structure used by tests. Wraps the generated `AranyaClient`
// instance plus metadata (device id and key bundle).
typedef struct {
    char name[64];
    AranyaClient client;
    AranyaDeviceId id;
    uint8_t *pk;
    size_t pk_len;
} Client;

// Team helper structure used by tests. Wraps the generated `AranyaTeamId`
// instance plus metadata (owner and members).
typedef struct {
    AranyaTeamId id;
    Client owner;
    Client member1;
    Client member2;
    AranyaSeedIkm team_ikm;
    /* Store default role IDs for use in tests */
    AranyaRoleId owner_role_id;
    AranyaRoleId admin_role_id;
    AranyaRoleId operator_role_id;
    AranyaRoleId member_role_id;
} Team;

// Helper to initialize the global config with defaults
static inline void aranya_test_config_init(struct aranya_test_config *cfg) {
    if (!cfg) return;
    cfg->daemon_path[0] = '\0';
    cfg->lib_search_path[0] = '\0';
    cfg->timeout_seconds = ARANYA_TEST_DEFAULT_TIMEOUT;
    cfg->verbose = false;
}

// Helper to set daemon path safely
static inline void aranya_test_set_daemon_path(struct aranya_test_config *cfg, const char *path) {
    if (!cfg || !path) return;

    size_t copy_len = ARANYA_PATH_MAX - 1;

    strncpy(cfg->daemon_path, path, copy_len);
    cfg->daemon_path[copy_len] = '\0';
}

// Small helper to optionally print diagnostics when verbose is enabled
#include <stdio.h>
#include <stdarg.h>
static inline void aranya_test_log(const struct aranya_test_config *cfg, const char *fmt, ...) {
    if (!cfg || !cfg->verbose) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

// Helper function to get role ID by name from a list of roles
static inline AranyaError get_role_id_by_name(const AranyaRole* role_list, size_t role_list_len, 
                                              const char* name, AranyaRoleId* role_id) {
    AranyaError err;
    for (size_t i = 0; i < role_list_len; i++) {
        AranyaRole role = role_list[i];
        const char* role_name = NULL;
        err = aranya_role_get_name(&role, &role_name);
        if (err != ARANYA_ERROR_SUCCESS) {
            return err;
        }
        if (strcmp(name, role_name) == 0) {
            err = aranya_role_get_id(&role, role_id);
            return err;
        }
    }
    return ARANYA_ERROR_OTHER;
}

// Sleep for a given number of milliseconds (cross-platform helper)
#include <unistd.h>
static inline void sleep_ms(unsigned int ms) {
    usleep(ms * 1000);
}

// Write daemon configuration file
#include <sys/types.h>
static inline void write_daemon_config(const char *cfg_path, const char *name, const char *run_dir,
                                       const char *shm_path, uint16_t sync_port) {
    FILE *f = fopen(cfg_path, "w");
    if (!f) {
        fprintf(stderr, "Failed to create daemon config: %s\n", cfg_path);
        return;
    }
    fprintf(f, "name = \"%s\"\n", name);
    fprintf(f, "runtime_dir = \"%s\"\n", run_dir);
    fprintf(f, "state_dir = \"%s/state\"\n", run_dir);
    fprintf(f, "cache_dir = \"%s/cache\"\n", run_dir);
    fprintf(f, "logs_dir = \"%s/logs\"\n", run_dir);
    fprintf(f, "config_dir = \"%s/config\"\n", run_dir);
    if (shm_path && shm_path[0]) {
        fprintf(f, "\n[afc]\n");
        fprintf(f, "enable = true\n");
        fprintf(f, "shm_path = \"%s\"\n", shm_path);
        fprintf(f, "max_chans = 100\n");
    }
    fprintf(f, "\n[sync.quic]\n");
    fprintf(f, "enable = true\n");
    fprintf(f, "addr = \"127.0.0.1:%u\"\n", (unsigned)sync_port);
    fclose(f);
}

// Spawn daemon process with custom configuration
#include <sys/wait.h>
static inline pid_t spawn_daemon_at(const char *daemon_path,
                                    const char *run_dir,
                                    const char *name,
                                    const char *shm_path,
                                    uint16_t sync_port) {
    char cfg_path[256];
    snprintf(cfg_path, sizeof(cfg_path), "%s/daemon.toml", run_dir);
    write_daemon_config(cfg_path, name, run_dir, shm_path, sync_port);
    
    pid_t pid = fork();
    if (pid == 0) {
        setenv("ARANYA_DAEMON", "aranya_daemon::aranya_daemon::api=debug", 1);
        execl(daemon_path, daemon_path, "--config", cfg_path, NULL);
        exit(1);
    }
    return pid;
}

// Spawn daemon process with simple configuration (uses "run" directory)
static inline pid_t spawn_daemon(const char *daemon_path, const char *name, const char *shm_path) {
    return spawn_daemon_at(daemon_path, "run", name, shm_path, 0);
}

#ifdef __cplusplus
}
#endif

#endif // ARANYA_CTEST_UTILS_H
