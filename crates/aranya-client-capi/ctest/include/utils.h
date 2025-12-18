#ifndef ARANYA_CTEST_UTILS_H
#define ARANYA_CTEST_UTILS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// Common constants used by tests
#define ARANYA_TEST_DEFAULT_TIMEOUT 1 // seconds

// Path buffers used by tests (size chosen for PATH_MAX portability)
#ifndef ARANYA_PATH_MAX
#define ARANYA_PATH_MAX 4096
#endif

// Global configuration structure that tests can read/modify
struct aranya_test_config {
    // Path to daemon executable used by tests. If empty, tests will try
    // to find daemon in default locations.
    char daemon_path[ARANYA_PATH_MAX];

    // Optional additional library search path (used to set env vars when
    // launching tests)
    char lib_search_path[ARANYA_PATH_MAX];

    // Per-test timeout in seconds for long-running operations
    unsigned int timeout_seconds;

    // Verbosity flag for tests to print extra diagnostics
    bool verbose;
};

// Extern global config instance (defined in one test translation unit or
// provided by test runner)
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
    if (!cfg)
        return;
    cfg->daemon_path[0] = '\0';
    cfg->lib_search_path[0] = '\0';
    cfg->timeout_seconds = ARANYA_TEST_DEFAULT_TIMEOUT;
    cfg->verbose = false;
}

// Small helper to optionally print diagnostics when verbose is enabled
static inline void aranya_test_log(const struct aranya_test_config *cfg,
                                   const char *fmt, ...) {
    if (!cfg || !cfg->verbose)
        return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

// Helper function to get role ID by name from a list of roles
static inline AranyaError get_role_id_by_name(const AranyaRole *role_list,
                                              size_t role_list_len,
                                              const char *name,
                                              AranyaRoleId *role_id) {
    AranyaError err;
    for (size_t i = 0; i < role_list_len; i++) {
        AranyaRole role = role_list[i];
        const char *role_name = NULL;
        err = aranya_role_get_name(&role, &role_name);
        if (err != ARANYA_ERROR_SUCCESS) {
            return err;
        }
        if (strncmp(name, role_name, strlen(name) + 1) == 0) {
            err = aranya_role_get_id(&role, role_id);
            return err;
        }
    }
    return ARANYA_ERROR_OTHER;
}

// Macro for printing AranyaError to stderr and returning the error.
// Does nothing if error value is ARANYA_SUCCESS.
#define EXPECT(M, E)                                                           \
    do {                                                                       \
        err = (E);                                                             \
        if (err != ARANYA_ERROR_SUCCESS) {                                     \
            fprintf(stderr, "%s\n", (M));                                      \
            goto exit;                                                         \
        }                                                                      \
    } while (0)

// Macro for printing client AranyaError to stderr and returning the error.
// Does nothing if error value is ARANYA_SUCCESS.
#define CLIENT_EXPECT(M, N, E)                                                 \
    do {                                                                       \
        err = (E);                                                             \
        if (err != ARANYA_ERROR_SUCCESS) {                                     \
            fprintf(stderr, "%s %s: %s\n", (M), (N),                           \
                    aranya_error_to_str(err));                                 \
            goto exit;                                                         \
        }                                                                      \
    } while (0)

// Helper function to create a team
static inline AranyaError create_team(AranyaClient *client, AranyaTeamId *team_id) {
    AranyaError err;
    AranyaCreateTeamConfigBuilder team_builder;
    AranyaCreateTeamConfig team_config;

    err = aranya_create_team_config_builder_init(&team_builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }

    err = aranya_create_team_config_build(&team_builder, &team_config);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }

    err = aranya_create_team(client, &team_config, team_id);
    return err;
}

#ifdef __cplusplus
}
#endif

#endif // ARANYA_CTEST_UTILS_H
