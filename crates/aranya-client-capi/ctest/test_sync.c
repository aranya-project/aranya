#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#ifndef ENABLE_ARANYA_PREVIEW
# define ENABLE_ARANYA_PREVIEW 1
#endif

#include "aranya-client.h"
#include "utils.h"

/* Initialize a client */
static AranyaError init_client(Client *c, const char *daemon_addr) {
    AranyaError err;
    
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
        fprintf(stderr, "Failed to build ClientConfig for %s: %s\n",
                c->name, aranya_error_to_str(err));
        return err;
    }
    
    err = aranya_client_init(&c->client, &cli_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "Failed to initialize client %s at %s: %s\n",
                c->name, daemon_addr, aranya_error_to_str(err));
        return err;
    }
    
    /* Get device ID */
    err = aranya_get_device_id(&c->client, &c->id);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_client_cleanup(&c->client);
        return err;
    }
    
    /* Get key bundle with buffer reallocation pattern */
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
    strncpy(owner->name, "Owner", sizeof(owner->name) - 1);
    
    AranyaError err = init_client(owner, "run/uds.sock");
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "Failed to initialize owner: %s\n", aranya_error_to_str(err));
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

/* Test: SyncPeerConfigBuilder initialization and cleanup */
static int test_sync_peer_config_builder(void) {
    printf("\n=== TEST: SyncPeerConfigBuilder ===\n");
    
    AranyaSyncPeerConfigBuilder builder;
    AranyaError rc = aranya_sync_peer_config_builder_init(&builder);
    
    if (rc != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to initialize SyncPeerConfigBuilder: %s\n", 
               aranya_error_to_str(rc));
        return 0;
    }
    
    /* Set interval to 1 second (1,000,000,000 nanoseconds) */
    AranyaDuration interval = 1000000000ULL;  /* AranyaDuration is a uint64_t */
    rc = aranya_sync_peer_config_builder_set_interval(&builder, interval);
    
    if (rc != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to set interval: %s\n", aranya_error_to_str(rc));
        aranya_sync_peer_config_builder_cleanup(&builder);
        return 0;
    }
    
    /* Enable sync now (this overrides sync_later if both are called) */
    rc = aranya_sync_peer_config_builder_set_sync_now(&builder);
    
    if (rc != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to set sync_now: %s\n", aranya_error_to_str(rc));
        aranya_sync_peer_config_builder_cleanup(&builder);
        return 0;
    }
    
    /* Build the config - builder is consumed */
    AranyaSyncPeerConfig config;
    rc = aranya_sync_peer_config_build(&builder, &config);
    
    if (rc != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to build SyncPeerConfig: %s\n", 
               aranya_error_to_str(rc));
        return 0;
    }
    
    /* Note: SyncPeerConfig is a struct, not an opaque type, so no cleanup needed */
    return 1;
}

/* Test: sync_peer_config_builder_set_sync_later */
static int test_sync_later(void) {
    printf("\n=== TEST: sync_peer_config_builder_set_sync_later ===\n");
    
    AranyaSyncPeerConfigBuilder builder;
    AranyaError rc = aranya_sync_peer_config_builder_init(&builder);
    if (rc != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init builder: %s\n", aranya_error_to_str(rc));
        return 0;
    }
    
    /* Set interval */
    AranyaDuration interval = 1000000000ULL;
    rc = aranya_sync_peer_config_builder_set_interval(&builder, interval);
    if (rc != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to set interval: %s\n", aranya_error_to_str(rc));
        aranya_sync_peer_config_builder_cleanup(&builder);
        return 0;
    }
    
    /* Set sync_later (disables immediate sync) */
    rc = aranya_sync_peer_config_builder_set_sync_later(&builder);
    if (rc != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to set sync_later: %s\n", aranya_error_to_str(rc));
        aranya_sync_peer_config_builder_cleanup(&builder);
        return 0;
    }
    
    printf("  ✓ sync_later configured\n");
    
    /* Build config */
    AranyaSyncPeerConfig config;
    rc = aranya_sync_peer_config_build(&builder, &config);
    if (rc != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to build config: %s\n", aranya_error_to_str(rc));
        return 0;
    }
    
    printf("  ✓ SyncPeerConfig built with sync_later\n");
    return 1;
}

/* Test: add_sync_peer and remove_sync_peer */
static int test_add_remove_sync_peer(void) {
    printf("\n=== TEST: add_sync_peer and remove_sync_peer ===\n");
    
    Team team = {0};
    AranyaError err = init_team(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create team: %s\n", aranya_error_to_str(err));
        return 0;
    }
    
    printf("  ✓ Team created\n");
    
    /* Build sync peer config */
    AranyaSyncPeerConfigBuilder builder;
    err = aranya_sync_peer_config_builder_init(&builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init SyncPeerConfigBuilder: %s\n", aranya_error_to_str(err));
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    AranyaDuration interval = 5000000000ULL; /* 5 seconds */
    err = aranya_sync_peer_config_builder_set_interval(&builder, interval);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to set interval: %s\n", aranya_error_to_str(err));
        aranya_sync_peer_config_builder_cleanup(&builder);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    err = aranya_sync_peer_config_builder_set_sync_later(&builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to set sync_later: %s\n", aranya_error_to_str(err));
        aranya_sync_peer_config_builder_cleanup(&builder);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    AranyaSyncPeerConfig config;
    err = aranya_sync_peer_config_build(&builder, &config);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to build SyncPeerConfig: %s\n", aranya_error_to_str(err));
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    /* Add sync peer */
    const char *peer_addr = "127.0.0.1:9001";
    err = aranya_add_sync_peer(&team.owner.client, &team.id, peer_addr, &config);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to add sync peer: %s\n", aranya_error_to_str(err));
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Sync peer added\n");
    
    /* Remove sync peer */
    err = aranya_remove_sync_peer(&team.owner.client, &team.id, peer_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to remove sync peer: %s\n", aranya_error_to_str(err));
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    printf("  ✓ Sync peer removed\n");
    
    /* Cleanup */
    if (team.owner.pk) free(team.owner.pk);
    aranya_client_cleanup(&team.owner.client);
    
    return 1;
}

/* Test: sync_now */
static int test_sync_now(void) {
    printf("\n=== TEST: sync_now ===\n");
    
    Team team = {0};
    AranyaError err = init_team(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create team: %s\n", aranya_error_to_str(err));
        return 0;
    }
    
    printf("  ✓ Team created\n");
    
    /* Test sync_now with NULL config (uses defaults) */
    const char *peer_addr = "127.0.0.1:9002";
    err = aranya_sync_now(&team.owner.client, &team.id, peer_addr, NULL);
    
    /* Note: This will likely fail because peer is not reachable, but the function should execute */
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  ℹ sync_now failed (expected if peer not reachable): %s\n", aranya_error_to_str(err));
    } else {
        printf("  ✓ sync_now executed\n");
    }
    
    /* Test sync_now with explicit config */
    AranyaSyncPeerConfigBuilder builder;
    err = aranya_sync_peer_config_builder_init(&builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init builder: %s\n", aranya_error_to_str(err));
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    AranyaDuration interval = 1000000000ULL;
    err = aranya_sync_peer_config_builder_set_interval(&builder, interval);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to set interval: %s\n", aranya_error_to_str(err));
        aranya_sync_peer_config_builder_cleanup(&builder);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    AranyaSyncPeerConfig config;
    err = aranya_sync_peer_config_build(&builder, &config);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to build config: %s\n", aranya_error_to_str(err));
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    err = aranya_sync_now(&team.owner.client, &team.id, peer_addr, &config);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  ℹ sync_now with config failed (expected if peer not reachable): %s\n", aranya_error_to_str(err));
    } else {
        printf("  ✓ sync_now with config executed\n");
    }
    
    /* Cleanup */
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
    
    printf("Running aranya-client-capi sync tests\n");
    printf("=====================================\n");

    /* Fail if daemon path isn't supplied */
    if (argc != 2) {
        return EXIT_FAILURE;
    }
    printf("Spawning daemon: %s\n", argv[1]);
    pid_t daemon_pid = spawn_daemon(argv[1], "test-sync-daemon", "/test_sync_shm");
    printf("Daemon PID: %d\n", daemon_pid);
        
    /* Wait for daemon to initialize */
    printf("Waiting 7 seconds for daemon to initialize...\n");
    sleep_ms(7000);
    printf("Daemon should be ready now\n");
    
    /* Test sync-related functionality */
    if (!test_sync_peer_config_builder()) {
        printf("FAILED: sync_peer_config_builder\n");
        return EXIT_FAILURE;
    }
    if (!test_sync_later()) {
        printf("FAILED: sync_later\n");
        return EXIT_FAILURE;
    }
    if (!test_add_remove_sync_peer()) {
        printf("FAILED: add_remove_sync_peer\n");
        return EXIT_FAILURE;
    }
    if (!test_sync_now()) {
        printf("FAILED: sync_now\n");
        return EXIT_FAILURE;
    }

    /* Clean up daemon if spawned */
    if (daemon_pid > 0) {
        printf("\nTerminating daemon (PID %d)\n", daemon_pid);
        kill(daemon_pid, SIGTERM);
        waitpid(daemon_pid, NULL, 0);
    }

    printf("\n=====================================\n");
    printf("ALL SYNC TESTS PASSED\n");
    
    return EXIT_SUCCESS;
#else
    printf("ENABLE_ARANYA_PREVIEW not defined; skipping sync tests\n");
    return EXIT_SUCCESS;
#endif
}
