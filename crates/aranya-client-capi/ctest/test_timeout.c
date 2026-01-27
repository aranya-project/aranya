#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aranya-client.h"
#include "utils.h"

/* Test: IPC timeout*/
static int test_timeout(const char *tmpdir) {
    printf("\n=== TEST: IPC timeout ===\n");

    AranyaError err;
    AranyaClient owner_client = {0};
    int result = EXIT_FAILURE;

    /* Construct daemon socket paths */
    char g_owner_uds[512];
    snprintf(g_owner_uds, sizeof(g_owner_uds), "%s/owner/uds.sock", tmpdir);

    /* Initialize owner client */
    AranyaClientConfigBuilder owner_builder;
    CLIENT_EXPECT("Failed to init owner config builder", "",
                  aranya_client_config_builder_init(&owner_builder));

    CLIENT_EXPECT("Failed to set owner daemon path", "",
                  aranya_client_config_builder_set_daemon_uds_path(
                      &owner_builder, g_owner_uds));

        CLIENT_EXPECT("Failed to set owner daemon path", "",
                  aranya_client_config_builder_set_daemon_uds_path(
                      &owner_builder, g_owner_uds));

    AranyaClientConfig owner_config;
    CLIENT_EXPECT("Failed to build owner config", "",
                  aranya_client_config_build(&owner_builder, &owner_config));

    CLIENT_EXPECT("Failed to init owner client", "",
                  aranya_client_init(&owner_client, &owner_config));

    /* Create team as owner */
    AranyaTeamId team_id;
    CLIENT_EXPECT("Failed to create team", "",
                  create_team(&owner_client, &team_id));

    printf("Team created by owner\n");

    result = EXIT_SUCCESS;

exit:
    aranya_client_cleanup(&owner_client);

    return result;
}

int main(int argc, const char *argv[]) {
    AranyaError exit_code;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <tmpdir>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *tmpdir = argv[1];

    printf("Running timeout test\n");

    exit_code = test_timeout(tmpdir);
    if (exit_code == EXIT_FAILURE) {
        fprintf(stderr, "FAILED: test_timeout\n");
    }
    return exit_code;
}
