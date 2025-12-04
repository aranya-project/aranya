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

#ifdef __cplusplus
}
#endif

#endif // ARANYA_CTEST_UTILS_H
