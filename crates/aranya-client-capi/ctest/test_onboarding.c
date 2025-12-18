#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aranya-client.h"
#include "utils.h"

/* Global daemon socket paths - constructed from temp directory argument */
static char g_owner_uds[512];
static char g_member_uds[512];

/* Test: Create team and onboard member*/
static int test_create_team_and_onboard_member(void) {
    printf("\n=== TEST: Add member to team ===\n");

    AranyaError err;
    AranyaClient owner_client = {0};
    AranyaClient member_client = {0};
    uint8_t *member_pk = NULL;
    int result = EXIT_FAILURE;

    /* Initialize owner client */
    AranyaClientConfigBuilder owner_builder;
    CLIENT_EXPECT("Failed to init owner config builder", "",
                  aranya_client_config_builder_init(&owner_builder));

    CLIENT_EXPECT("Failed to set owner daemon path", "",
                  aranya_client_config_builder_set_daemon_uds_path(
                      &owner_builder, g_owner_uds));

    AranyaClientConfig owner_config;
    CLIENT_EXPECT("Failed to build owner config", "",
                  aranya_client_config_build(&owner_builder, &owner_config));

    CLIENT_EXPECT("Failed to init owner client", "",
                  aranya_client_init(&owner_client, &owner_config));

    /* Create team as owner */
    AranyaCreateTeamConfigBuilder team_builder;
    CLIENT_EXPECT("Failed to init team config builder", "",
                  aranya_create_team_config_builder_init(&team_builder));

    AranyaCreateTeamConfig team_config;
    CLIENT_EXPECT("Failed to build team config", "",
                  aranya_create_team_config_build(&team_builder, &team_config));

    AranyaTeamId team_id;
    CLIENT_EXPECT("Failed to create team", "",
                  aranya_create_team(&owner_client, &team_config, &team_id));

    printf("Team created by owner\n");

    /* Initialize member client */
    AranyaClientConfigBuilder member_builder;
    CLIENT_EXPECT("Failed to init member config builder", "",
                  aranya_client_config_builder_init(&member_builder));

    CLIENT_EXPECT("Failed to set member daemon path", "",
                  aranya_client_config_builder_set_daemon_uds_path(
                      &member_builder, g_member_uds));

    AranyaClientConfig member_config;
    CLIENT_EXPECT("Failed to build member config", "",
                  aranya_client_config_build(&member_builder, &member_config));

    CLIENT_EXPECT("Failed to init member client", "",
                  aranya_client_init(&member_client, &member_config));

    /* Get member's key bundle */
    size_t member_pk_len = 1;
    member_pk = calloc(1, 1);
    if (!member_pk) {
        fprintf(stderr, "Failed to allocate memory for member key bundle\n");
        goto exit;
    }

    err = aranya_get_key_bundle(&member_client, member_pk, &member_pk_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        member_pk = realloc(member_pk, member_pk_len);
        if (!member_pk) {
            fprintf(stderr,
                    "Failed to reallocate memory for member key bundle\n");
            goto exit;
        }
        CLIENT_EXPECT(
            "Failed to get member key bundle", "",
            aranya_get_key_bundle(&member_client, member_pk, &member_pk_len));
    } else if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "Failed to get member key bundle: %s\n",
                aranya_error_to_str(err));
        goto exit;
    }

    printf("Got member key bundle (%zu bytes)\n", member_pk_len);

    /* Add member to team */
    CLIENT_EXPECT("Failed to add member to team", "",
                  aranya_add_device_to_team(&owner_client, &team_id, member_pk,
                                            member_pk_len, NULL));

    printf("Member added to team successfully\n");

    result = EXIT_SUCCESS;

exit:
    free(member_pk);
    aranya_client_cleanup(&member_client);
    aranya_client_cleanup(&owner_client);

    return result;
}

int main(int argc, const char *argv[]) {
    AranyaError exit_code;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <daemon> <tmpdir>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *tmpdir = argv[2];
    snprintf(g_owner_uds, sizeof(g_owner_uds), "%s/owner/uds.sock", tmpdir);
    snprintf(g_member_uds, sizeof(g_member_uds), "%s/member/uds.sock", tmpdir);

    printf("Running onboarding test\n");

    exit_code = test_create_team_and_onboard_member();
    if (exit_code == EXIT_FAILURE) {
        fprintf(stderr, "FAILED: test_create_team_and_onboard_member\n");
    }
    return exit_code;
}
