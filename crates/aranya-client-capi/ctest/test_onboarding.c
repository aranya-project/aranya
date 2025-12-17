#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#ifndef ENABLE_ARANYA_PREVIEW
# define ENABLE_ARANYA_PREVIEW 1
#endif

#include "include/aranya-client.h"
#include "include/utils.h"

/* Global daemon socket paths - set by wrapper script spawning daemons */
static const char g_owner_uds[] = "/tmp/onboarding-run-owner/uds.sock";
static const char g_member_uds[] = "/tmp/onboarding-run-member/uds.sock";

/* Test: Create team and onboard member*/
static int test_create_team_and_onboard_member(void) {
    printf("\n=== TEST: Add member to team ===\n");
    
    AranyaError err;
    
    /* Initialize owner client */
    AranyaClientConfigBuilder owner_builder;
    err = aranya_client_config_builder_init(&owner_builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init owner config builder: %s\n", aranya_error_to_str(err));
        return 1;
    }
    
    err = aranya_client_config_builder_set_daemon_uds_path(&owner_builder, g_owner_uds);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to set owner daemon path: %s\n", aranya_error_to_str(err));
        aranya_client_config_builder_cleanup(&owner_builder);
        return 1;
    }
    
    AranyaClientConfig owner_config;
    err = aranya_client_config_build(&owner_builder, &owner_config);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to build owner config: %s\n", aranya_error_to_str(err));
        return 1;
    }
    
    AranyaClient owner_client;
    err = aranya_client_init(&owner_client, &owner_config);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init owner client: %s\n", aranya_error_to_str(err));
        return 1;
    }
    
    /* Create team as owner */
    AranyaCreateTeamConfigBuilder team_builder;
    err = aranya_create_team_config_builder_init(&team_builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init team config builder: %s\n", aranya_error_to_str(err));
        aranya_client_cleanup(&owner_client);
        return 1;
    }
    
    AranyaCreateTeamConfig team_config;
    err = aranya_create_team_config_build(&team_builder, &team_config);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to build team config: %s\n", aranya_error_to_str(err));
        aranya_client_cleanup(&owner_client);
        return 1;
    }
    
    AranyaTeamId team_id;
    err = aranya_create_team(&owner_client, &team_config, &team_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create team: %s\n", aranya_error_to_str(err));
        aranya_client_cleanup(&owner_client);
        return 1;
    }
    
    printf("  Team created by owner\n");
    
    /* Initialize member client */
    AranyaClientConfigBuilder member_builder;
    err = aranya_client_config_builder_init(&member_builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init member config builder: %s\n", aranya_error_to_str(err));
        aranya_client_cleanup(&owner_client);
        return 1;
    }
    
    err = aranya_client_config_builder_set_daemon_uds_path(&member_builder, g_member_uds);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to set member daemon path: %s\n", aranya_error_to_str(err));
        aranya_client_config_builder_cleanup(&member_builder);
        aranya_client_cleanup(&owner_client);
        return 1;
    }
    
    AranyaClientConfig member_config;
    err = aranya_client_config_build(&member_builder, &member_config);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to build member config: %s\n", aranya_error_to_str(err));
        aranya_client_cleanup(&owner_client);
        return 1;
    }
    
    AranyaClient member_client;
    err = aranya_client_init(&member_client, &member_config);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init member client: %s\n", aranya_error_to_str(err));
        aranya_client_cleanup(&owner_client);
        return 1;
    }
    
    /* Get member's key bundle */
    size_t member_pk_len = 1;
    uint8_t *member_pk = calloc(1, 1);
    if (!member_pk) {
        printf("  Failed to allocate memory for member key bundle\n");
        aranya_client_cleanup(&member_client);
        aranya_client_cleanup(&owner_client);
        return 1;
    }
    
    err = aranya_get_key_bundle(&member_client, member_pk, &member_pk_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        member_pk = realloc(member_pk, member_pk_len);
        if (!member_pk) {
            printf("  Failed to reallocate memory for member key bundle\n");
            aranya_client_cleanup(&member_client);
            aranya_client_cleanup(&owner_client);
            return 1;
        }
        err = aranya_get_key_bundle(&member_client, member_pk, &member_pk_len);
    }
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to get member key bundle: %s\n", aranya_error_to_str(err));
        free(member_pk);
        aranya_client_cleanup(&member_client);
        aranya_client_cleanup(&owner_client);
        return 1;
    }
    
    printf("  Got member key bundle (%zu bytes)\n", member_pk_len);
    
    /* Add member to team (without role for now - will be NULL) */
    err = aranya_add_device_to_team(&owner_client, &team_id, member_pk, member_pk_len, NULL);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to add member to team: %s\n", aranya_error_to_str(err));
        free(member_pk);
        aranya_client_cleanup(&member_client);
        aranya_client_cleanup(&owner_client);
        return 1;
    }
    
    printf("  Member added to team successfully\n");
    
    /* Cleanup */
    free(member_pk);
    aranya_client_cleanup(&member_client);
    aranya_client_cleanup(&owner_client);
    
    return 0;
}

int main(int argc, const char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "usage: `%s <daemon>`\n", argv[0]);
        return EXIT_FAILURE;
    }

    printf("Running aranya-client-capi basic subtests\n");
    
    if (test_create_team_and_onboard_member() != 0) {
        fprintf(stderr, "FAILED: test_create_team_and_onboard_member\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
