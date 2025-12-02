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

/* Utility: millisecond sleep */
static void sleep_ms(unsigned int ms) {
    usleep(ms * 1000);
}

/* Utility: spawn daemon process */
static pid_t spawn_daemon(const char *daemon_path) {
    /* Create short runtime directory to avoid Unix socket path length limits */
    system("rm -rf run && mkdir -p run");
    
    /* Create required subdirectories */
    system("mkdir -p run/state run/cache run/logs run/config");
    
    /* Create daemon config file */
    FILE *f = fopen("run/daemon.toml", "w");
    if (!f) {
        fprintf(stderr, "Failed to create daemon config\n");
        return -1;
    }
    fprintf(f, "name = \"test-query-daemon\"\n");
    fprintf(f, "runtime_dir = \"run\"\n");
    fprintf(f, "state_dir = \"run/state\"\n");
    fprintf(f, "cache_dir = \"run/cache\"\n");
    fprintf(f, "logs_dir = \"run/logs\"\n");
    fprintf(f, "config_dir = \"run/config\"\n");
    fprintf(f, "\n");
    fprintf(f, "[afc]\n");
    fprintf(f, "enable = true\n");
    fprintf(f, "shm_path = \"/test_query_shm\"\n");
    fprintf(f, "max_chans = 100\n");
    fprintf(f, "\n");
    fprintf(f, "[sync.quic]\n");
    fprintf(f, "enable = true\n");
    fprintf(f, "addr = \"127.0.0.1:0\"\n");
    fclose(f);
    
    pid_t pid = fork();
    if (pid == 0) {
        /* Child process */
        setenv("ARANYA_DAEMON", "aranya_daemon::aqc=trace,aranya_daemon::api=debug", 1);
        execl(daemon_path, daemon_path, "--config", "run/daemon.toml", NULL);
        exit(1);
    }
    return pid;
}

/* Initialize a client */
static AranyaError init_client(Client *c, const char* name, const char *daemon_addr) {
    AranyaError err;
    c->name = name;
    
    /* Build AQC config */
    AranyaAqcConfigBuilder aqc_builder;
    err = aranya_aqc_config_builder_init(&aqc_builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_aqc_config_builder_cleanup(&aqc_builder);
        return err;
    }
    const char *aqc_addr = "127.0.0.1:0";
    err = aranya_aqc_config_builder_set_address(&aqc_builder, aqc_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_aqc_config_builder_cleanup(&aqc_builder);
        return err;
    }
    
    AranyaAqcConfig aqc_cfg;
    err = aranya_aqc_config_build(&aqc_builder, &aqc_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
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
    
    err = aranya_client_config_builder_set_aqc_config(&cli_builder, &aqc_cfg);
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
    
    AranyaError err = init_client(owner, "owner", "run/uds.sock");
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
    
    return ARANYA_ERROR_SUCCESS;
}

/* Simple pass/fail reporter */
static void report(const char *name, int ok, int *fails) {
    printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) (*fails)++;
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
    
    /* Create a second device and add it */
    Client device;
    memset(&device, 0, sizeof(Client));
    
    err = init_client(&device, "Device", "run/uds.sock");
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init device: %s\n", aranya_error_to_str(err));
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    err = aranya_add_device_to_team(&team.owner.client, &team.id, device.pk, device.pk_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to add device: %s\n", aranya_error_to_str(err));
        if (device.pk) free(device.pk);
        aranya_client_cleanup(&device.client);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Device added to team\n");
    
    /* Query devices with buffer reallocation */
    size_t devices_len = 1;
    AranyaDeviceId *devices = calloc(devices_len, sizeof(AranyaDeviceId));
    
    err = aranya_query_devices_on_team(&team.owner.client, &team.id, devices, &devices_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        devices = realloc(devices, devices_len * sizeof(AranyaDeviceId));
        err = aranya_query_devices_on_team(&team.owner.client, &team.id, devices, &devices_len);
    }
    
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to query devices: %s\n", aranya_error_to_str(err));
        free(devices);
        if (device.pk) free(device.pk);
        aranya_client_cleanup(&device.client);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Found %zu device(s) on team\n", devices_len);
    
    /* Cleanup */
    free(devices);
    if (device.pk) free(device.pk);
    aranya_client_cleanup(&device.client);
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
    
    err = aranya_query_device_keybundle(&team.owner.client, &team.id, &team.owner.id, 
                                        keybundle, &keybundle_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        keybundle = realloc(keybundle, keybundle_len);
        err = aranya_query_device_keybundle(&team.owner.client, &team.id, &team.owner.id, 
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
    err = aranya_create_label(&team.owner.client, &team.id, "QUERY_TEST_LABEL", &label_id);
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
    
    err = aranya_query_labels(&team.owner.client, &team.id, labels, &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        labels = realloc(labels, labels_len * sizeof(AranyaLabelId));
        err = aranya_query_labels(&team.owner.client, &team.id, labels, &labels_len);
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
    err = aranya_query_label_exists(&team.owner.client, &team.id, &label_id, &exists);
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
    
    /* Create a device */
    Client device;
    memset(&device, 0, sizeof(Client));
    
    err = init_client(&device, "Device", "run/uds.sock");
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init device: %s\n", aranya_error_to_str(err));
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    err = aranya_add_device_to_team(&team.owner.client, &team.id, device.pk, device.pk_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to add device: %s\n", aranya_error_to_str(err));
        if (device.pk) free(device.pk);
        aranya_client_cleanup(&device.client);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    /* Create and assign a label */
    AranyaLabelId label_id;
    err = aranya_create_label(&team.owner.client, &team.id, "DEVICE_QUERY_LABEL", &label_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create label: %s\n", aranya_error_to_str(err));
        if (device.pk) free(device.pk);
        aranya_client_cleanup(&device.client);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    err = aranya_assign_label(&team.owner.client, &team.id, &device.id, 
                             &label_id, ARANYA_CHAN_OP_SEND_RECV);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to assign label: %s\n", aranya_error_to_str(err));
        if (device.pk) free(device.pk);
        aranya_client_cleanup(&device.client);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Label assigned to device\n");
    
    /* Query device label assignments */
    size_t labels_len = 1;
    AranyaLabelId *labels = calloc(labels_len, sizeof(AranyaLabelId));
    
    err = aranya_query_device_label_assignments(&team.owner.client, &team.id, &device.id, 
                                                labels, &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        labels = realloc(labels, labels_len * sizeof(AranyaLabelId));
        err = aranya_query_device_label_assignments(&team.owner.client, &team.id, &device.id, 
                                                    labels, &labels_len);
    }
    
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to query device label assignments: %s\n", aranya_error_to_str(err));
        free(labels);
        if (device.pk) free(device.pk);
        aranya_client_cleanup(&device.client);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Device has %zu label(s) assigned\n", labels_len);
    
    /* Cleanup */
    free(labels);
    if (device.pk) free(device.pk);
    aranya_client_cleanup(&device.client);
    if (team.owner.pk) free(team.owner.pk);
    aranya_client_cleanup(&team.owner.client);
    
    return 1;
}

int main(int argc, const char *argv[]) {
    int fails = 0;
    pid_t daemon_pid = -1;

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
    if (argc == 2) {
        printf("Spawning daemon: %s\n", argv[1]);
        daemon_pid = spawn_daemon(argv[1]);
        printf("Daemon PID: %d\n", daemon_pid);
        
        /* Wait for daemon to initialize */
        printf("Waiting 7 seconds for daemon to initialize...\n");
        sleep_ms(7000);
        printf("Daemon should be ready now\n");
    }

    /* Test query operations */
    report("query_devices_on_team", test_query_devices_on_team(), &fails);
    report("query_device_keybundle", test_query_device_keybundle(), &fails);
    report("query_labels", test_query_labels(), &fails);
    report("query_device_label_assignments", test_query_device_label_assignments(), &fails);

    /* Clean up daemon if spawned */
    if (daemon_pid > 0) {
        printf("\nTerminating daemon (PID %d)\n", daemon_pid);
        kill(daemon_pid, SIGTERM);
        waitpid(daemon_pid, NULL, 0);
    }

    printf("\n======================================\n");
    if (fails == 0) {
        printf("ALL QUERY TESTS PASSED\n");
        return EXIT_SUCCESS;
    } else {
        printf("%d QUERY TEST(S) FAILED\n", fails);
        return EXIT_FAILURE;
    }
#else
    printf("ENABLE_ARANYA_PREVIEW not defined; skipping query tests\n");
    return EXIT_SUCCESS;
#endif
}
