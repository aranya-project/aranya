#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdbool.h>

#ifndef ENABLE_ARANYA_PREVIEW
# define ENABLE_ARANYA_PREVIEW 1
#endif

#include "aranya-client.h"
#include "utils.h"

/* Initialize a client */
static AranyaError init_client(Client *c, const char* name, const char *daemon_addr) {
    AranyaError err;
    if (name) {
        snprintf(c->name, sizeof(c->name), "%s", name);
    } else {
        c->name[0] = '\0';
    }
    c->name[sizeof(c->name) - 1] = '\0';

    
    /* Build client config */
    AranyaClientConfigBuilder cli_builder;
    err = aranya_client_config_builder_init(&cli_builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_client_config_builder_cleanup(&cli_builder);
        return err;
    }
    err = aranya_client_config_builder_set_daemon_uds_path(&cli_builder, daemon_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_client_config_builder_cleanup(&cli_builder);
        return err;
    }
    
    AranyaClientConfig cli_cfg;
    err = aranya_client_config_build(&cli_builder, &cli_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    err = aranya_client_init(&c->client, &cli_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Get device ID */
    err = aranya_get_device_id(&c->client, &c->id);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_client_cleanup(&c->client);
        return err;
    }
    
    /* Get key bundle */
    c->pk_len = 1;
    c->pk = calloc(1, 1);
    
    err = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        c->pk = realloc(c->pk, c->pk_len);
        err = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    }
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_client_cleanup(&c->client);
        return err;
    }
    
    return ARANYA_ERROR_SUCCESS;
}

/* Initialize a team with owner */
static AranyaError init_team(Team *t) {
    Client *owner = &t->owner;
    memset(owner, 0, sizeof(Client));
    
    AranyaError err = init_client(owner, "Owner", "run/uds.sock");
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Build QUIC sync config */
    AranyaCreateTeamQuicSyncConfigBuilder owner_quic_build;
    err = aranya_create_team_quic_sync_config_builder_init(&owner_quic_build);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    err = aranya_create_team_quic_sync_config_generate(&owner_quic_build);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    AranyaCreateTeamQuicSyncConfig owner_quic_cfg;
    err = aranya_create_team_quic_sync_config_build(&owner_quic_build, &owner_quic_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Build team config */
    AranyaCreateTeamConfigBuilder owner_build;
    err = aranya_create_team_config_builder_init(&owner_build);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    err = aranya_create_team_config_builder_set_quic_syncer(&owner_build, &owner_quic_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    AranyaCreateTeamConfig owner_cfg;
    err = aranya_create_team_config_build(&owner_build, &owner_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Create the team */
    err = aranya_create_team(&owner->client, &owner_cfg, &t->id);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Get the initial Owner role (created automatically with the team) */
    size_t initial_roles_len = 1;
    AranyaRole initial_roles[1];
    err = aranya_team_roles(&owner->client, &t->id, initial_roles, &initial_roles_len);
    if (err != ARANYA_ERROR_SUCCESS || initial_roles_len != 1) {
        return err != ARANYA_ERROR_SUCCESS ? err : ARANYA_ERROR_OTHER;
    }
    
    err = aranya_role_get_id(&initial_roles[0], &t->owner_role_id);
    aranya_role_cleanup(&initial_roles[0]);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Setup default roles (Admin, Operator, Member) */
    AranyaRole default_roles[10];
    size_t default_roles_len = 10;
    err = aranya_setup_default_roles(&owner->client, &t->id, &t->owner_role_id, default_roles, &default_roles_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Get admin role ID for later use */
    err = get_role_id_by_name(default_roles, default_roles_len, "admin", &t->admin_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        for (size_t i = 0; i < default_roles_len; i++) {
            aranya_role_cleanup(&default_roles[i]);
        }
        return err;
    }
    
    /* Get operator role ID for later use */
    err = get_role_id_by_name(default_roles, default_roles_len, "operator", &t->operator_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        for (size_t i = 0; i < default_roles_len; i++) {
            aranya_role_cleanup(&default_roles[i]);
        }
        return err;
    }
    
    /* Get member role ID for later use */
    err = get_role_id_by_name(default_roles, default_roles_len, "member", &t->member_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        for (size_t i = 0; i < default_roles_len; i++) {
            aranya_role_cleanup(&default_roles[i]);
        }
        return err;
    }
    
    /* Cleanup roles */
    for (size_t i = 0; i < default_roles_len; i++) {
        aranya_role_cleanup(&default_roles[i]);
    }
    
    return ARANYA_ERROR_SUCCESS;
}

/* Test: query_devices_on_team */
static int test_query_devices_on_team(void) {
    printf("\n=== TEST: query_devices_on_team ===\n");
    
    Team team = {0};
    AranyaError err = init_team(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create team: %s\n", aranya_error_to_str(err));
        return 0;
    }
    
    /* Query devices (should find at least the owner) */
    size_t devices_len = 1;
    AranyaDeviceId *devices = calloc(devices_len, sizeof(AranyaDeviceId));
    
    err = aranya_team_devices(&team.owner.client, &team.id, devices, &devices_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        devices = realloc(devices, devices_len * sizeof(AranyaDeviceId));
        err = aranya_team_devices(&team.owner.client, &team.id, devices, &devices_len);
    }
    
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to query devices: %s\n", aranya_error_to_str(err));
        free(devices);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Found %zu device(s) on team\n", devices_len);
    
    /* Cleanup */
    free(devices);
    if (team.owner.pk) free(team.owner.pk);
    aranya_client_cleanup(&team.owner.client);
    
    return 1;
}

/* Test: query_device_keybundle */
static int test_query_device_keybundle(void) {
    printf("\n=== TEST: query_device_keybundle ===\n");
    
    Team team = {0};
    AranyaError err = init_team(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create team: %s\n", aranya_error_to_str(err));
        return 0;
    }
    
    /* Query owner's keybundle */
    size_t keybundle_len = 1;
    uint8_t *keybundle = calloc(keybundle_len, 1);
    
    err = aranya_team_device_keybundle(&team.owner.client, &team.id, &team.owner.id, 
                                        keybundle, &keybundle_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        keybundle = realloc(keybundle, keybundle_len);
        err = aranya_team_device_keybundle(&team.owner.client, &team.id, &team.owner.id, 
                                            keybundle, &keybundle_len);
    }
    
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to query keybundle: %s\n", aranya_error_to_str(err));
        free(keybundle);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Queried keybundle (%zu bytes)\n", keybundle_len);
    
    /* Cleanup */
    free(keybundle);
    if (team.owner.pk) free(team.owner.pk);
    aranya_client_cleanup(&team.owner.client);
    
    return 1;
}

/* Test: query_labels and query_label_exists */
static int test_query_labels(void) {
    printf("\n=== TEST: query_labels and query_label_exists ===\n");
    
    Team team = {0};
    AranyaError err = init_team(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create team: %s\n", aranya_error_to_str(err));
        return 0;
    }
    
    /* Create a label */
    AranyaLabelId label_id;
    err = aranya_create_label(&team.owner.client, &team.id, "QUERY_TEST_LABEL", &team.owner_role_id, &label_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create label: %s\n", aranya_error_to_str(err));
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Label created\n");
    
    /* Query labels */
    size_t labels_len = 1;
    AranyaLabelId *labels = calloc(labels_len, sizeof(AranyaLabelId));
    
    err = aranya_team_labels(&team.owner.client, &team.id, labels, &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        labels = realloc(labels, labels_len * sizeof(AranyaLabelId));
        err = aranya_team_labels(&team.owner.client, &team.id, labels, &labels_len);
    }
    
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to query labels: %s\n", aranya_error_to_str(err));
        free(labels);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Found %zu label(s)\n", labels_len);
    
    /* Check if label exists */
    bool exists = false;
    err = aranya_team_label_exists(&team.owner.client, &team.id, &label_id, &exists);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to query label exists: %s\n", aranya_error_to_str(err));
        free(labels);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Label exists: %s\n", exists ? "yes" : "no");
    
    /* Cleanup */
    free(labels);
    if (team.owner.pk) free(team.owner.pk);
    aranya_client_cleanup(&team.owner.client);
    
    return 1;
}

/* Test: query_device_label_assignments */
static int test_query_device_label_assignments(void) {
    printf("\n=== TEST: query_device_label_assignments ===\n");
    
    Team team = {0};
    AranyaError err = init_team(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create team: %s\n", aranya_error_to_str(err));
        return 0;
    }
    

    /* Query device label assignments */
    size_t labels_len = 1;
    AranyaLabelId *labels = calloc(labels_len, sizeof(AranyaLabelId));
    
    err = aranya_team_device_label_assignments(&team.owner.client, &team.id, &team.owner.id, 
                                                labels, &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        labels = realloc(labels, labels_len * sizeof(AranyaLabelId));
        err = aranya_team_device_label_assignments(&team.owner.client, &team.id, &team.owner.id, 
                                                    labels, &labels_len);
    }
    
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to query owner label assignments: %s\n", aranya_error_to_str(err));
        free(labels);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Queried %zu label(s) for owner device (query function works)\n", labels_len);
    
    /* Cleanup */
    free(labels);
    if (team.owner.pk) free(team.owner.pk);
    aranya_client_cleanup(&team.owner.client);
    
    return 1;
}

int main(int argc, const char *argv[]) {
#if defined(ENABLE_ARANYA_PREVIEW)
    /* Set client logging environment variable */
    setenv("ARANYA_CAPI", "aranya=debug", 1);
    
    /* Initialize logging subsystem */
    AranyaError err = aranya_init_logging();
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "Failed to initialize logging: %s\n", aranya_error_to_str(err));
        return EXIT_FAILURE;
    }
    
    printf("Running aranya-client-capi query tests\n");
    printf("======================================\n");

    /* Spawn daemon if path provided */
    if (argc != 2) {
        return EXIT_FAILURE;
    }
    printf("Spawning daemon: %s\n", argv[1]);
    pid_t daemon_pid = spawn_daemon(argv[1], "test-query-daemon", "/test_query_shm");
    printf("Daemon PID: %d\n", daemon_pid);

    /* Wait for daemon to initialize */
    printf("Waiting 7 seconds for daemon to initialize...\n");
    sleep_ms(7000);
    printf("Daemon should be ready now\n");

    int exit_code = EXIT_SUCCESS;
    
    /* Test query operations */
    if (!test_query_devices_on_team()) {
        printf("FAILED: query_devices_on_team\n");
        exit_code = EXIT_FAILURE;
    }
    if (!test_query_device_keybundle()) {
        printf("FAILED: query_device_keybundle\n");
        exit_code = EXIT_FAILURE;
    }
    if (!test_query_labels()) {
        printf("FAILED: query_labels\n");
        exit_code = EXIT_FAILURE;
    }
    if (!test_query_device_label_assignments()) {
        printf("FAILED: query_device_label_assignments\n");
        exit_code = EXIT_FAILURE;
    }

    /* Clean up daemon if spawned */
    if (daemon_pid > 0) {
        printf("\nTerminating daemon (PID %d)\n", daemon_pid);
        kill(daemon_pid, SIGTERM);
        waitpid(daemon_pid, NULL, 0);
    }

    printf("\n======================================\n");
    if (exit_code == EXIT_SUCCESS) {
        printf("ALL QUERY TESTS PASSED\n");
    } else {
        printf("SOME QUERY TESTS FAILED\n");
    }
    return exit_code;
#else
    printf("ENABLE_ARANYA_PREVIEW not defined; skipping query tests\n");
    return EXIT_SUCCESS;
#endif
}
