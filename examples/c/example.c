/*
 * Copyright (c) SpiderOak, Inc. All rights reserved.
 */
/**
 * @file example.c
 * @brief Example C application using the Aranya client library.
 */

// Note: this file is formatted with `clang-format`.

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aranya-client.h"

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

// Default size for allocated data buffers.
#define BUFFER_LEN 256

// Number of clients on an Aranya team.
#define NUM_CLIENTS 5

static AranyaError read_api_pk(uint8_t **api_pk, size_t *api_pk_len,
                               const char *name) {
    AranyaError err = ARANYA_ERROR_OTHER;
    FILE *f         = NULL;
    char *path      = NULL;

    if (api_pk == NULL || api_pk_len == NULL) {
        abort();
    }
    *api_pk     = NULL;
    *api_pk_len = 0;

    int n = snprintf(NULL, 0, "out/%s/api_pk", name);
    if (n < 0) {
        perror("snprintf failed");
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }
    size_t path_len = n;
    path            = calloc(path_len + 1, sizeof(char));
    if (path == NULL) {
        abort();
    }
    n = snprintf(path, path_len + 1, "out/%s/api_pk", name);
    if (n < 0) {
        perror("snprintf failed");
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }
    f = fopen(path, "rb");
    if (f == NULL) {
        perror("fopen failed");
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }
    if (fseek(f, 0, SEEK_END) < 0) {
        perror("fseek(..., 0, SEEK_END) failed");
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }
    long api_pk_hex_len = ftell(f);
    if (api_pk_hex_len < 0) {
        perror("ftell failed");
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }
    if (fseek(f, 0, SEEK_SET) < 0) {
        perror("fseek(..., 0, SEEK_SET) failed");
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }
    char *api_pk_hex = calloc(api_pk_hex_len + 1, sizeof(char));
    if (api_pk_hex == NULL) {
        abort();
    }
    if (fread(api_pk_hex, sizeof(char), api_pk_hex_len, f) < 1) {
        perror("fread failed");
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }

    // Just in case: chop off any trailing whitespace.
    while (api_pk_hex_len > 0 && isspace(api_pk_hex[api_pk_hex_len - 1])) {
        api_pk_hex_len -= 1;
    }
    api_pk_hex[api_pk_hex_len] = 0;

    *api_pk_len = api_pk_hex_len / 2;
    *api_pk     = calloc(*api_pk_len, sizeof(uint8_t));
    if (*api_pk == NULL) {
        abort();
    }
    size_t nw = 0;
    err = aranya_decode_hex(*api_pk, *api_pk_len, (const uint8_t *)api_pk_hex,
                            (size_t)api_pk_hex_len, &nw);
    EXPECT("unable to decode hex", err);

    if (nw != *api_pk_len) {
        fprintf(stderr, "bug in aranya_decode_hex: %zu != %zu\n", nw,
                *api_pk_len);
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }

exit:
    free(path);
    if (f != NULL) {
        fclose(f);
    }
    if (err != ARANYA_ERROR_SUCCESS) {
        free(*api_pk);
        *api_pk_len = 0;
    }
    return ARANYA_ERROR_SUCCESS;
}

// Team members enum. Can index into team member arrays.
typedef enum {
    OWNER,
    ADMIN,
    OPERATOR,
    MEMBERA,
    MEMBERB,
} Members;

// List of Unix domain socket paths for the Aranya clients.
const char *daemon_socks[] = {"out/owner/uds.sock", "out/admin/uds.sock",
                              "out/operator/uds.sock", "out/membera/uds.sock",
                              "out/memberb/uds.sock"};

// List of names for the Aranya clients.
const char *client_names[] = {"owner", "admin", "operator", "membera",
                              "memberb"};

// List of sync addresses.
const AranyaAddr sync_addrs[] = {"127.0.0.1:10001", "127.0.0.1:10002",
                                 "127.0.0.1:10003", "127.0.0.1:10004",
                                 "127.0.0.1:10005"};

// List of AQC addresses.
const char *aqc_addrs[] = {"127.0.0.1:11001", "127.0.0.1:11002",
                           "127.0.0.1:11003", "127.0.0.1:11004",
                           "127.0.0.1:11005"};

// Aranya client.
typedef struct {
    // Name of Aranya client.
    const char *name;
    // Pointer to Aranya client.
    AranyaClient client;
    // Aranya client's serialized public key bundle.
    uint8_t *pk;
    // Aranya client's serialized public key bundle length.
    size_t pk_len;
    // Aranya client's public id.
    AranyaDeviceId id;
} Client;

// Aranya team.
//
// Contains the team ID and all Aranya clients for the devices on this example's
// team.
typedef struct {
    AranyaTeamId id;
    uint8_t *init_cmd;
    size_t init_cmd_len;
    union {
        struct {
            // Team owner.
            Client owner;
            // Team admin.
            Client admin;
            // Team operator.
            Client operator;
            // Team member a.
            Client membera;
            // Team member b.
            Client memberb;
        } clients;
        Client clients_arr[NUM_CLIENTS];
    };
} Team;

// Forward Declarations
AranyaError init_client(Client *c, const char *name, const char *daemon_addr,
                        const uint8_t *api_pk, size_t api_pk_len,
                        const char *aqc_addr);
AranyaError init_team(Team *t);
AranyaError add_sync_peers(Team *t, AranyaSyncPeerConfig *cfg);
AranyaError add_team_to_devices(Team* t);
AranyaError run(Team *t);
AranyaError run_aqc_example(Team *t);
AranyaError cleanup_team(Team *t);

// Initialize an Aranya `Client` with the given parameters.
AranyaError init_client(Client *c, const char *name, const char *daemon_addr,
                        const uint8_t *api_pk, size_t api_pk_len,
                        const char *aqc_addr) {
    AranyaError err;
    c->name = name;

    struct AranyaAqcConfigBuilder aqc_builder;
    err = aranya_aqc_config_builder_init(&aqc_builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to initialize `AranyaAqcConfigBuilder`\n");
        aranya_aqc_config_builder_cleanup(&aqc_builder);
        return err;
    }
    err = aranya_aqc_config_builder_set_address(&aqc_builder, aqc_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to set AQC server address\n");
        aranya_aqc_config_builder_cleanup(&aqc_builder);
        return err;
    }

    // NB: A builder's "_build" method consumes the builder, so
    // do _not_ call "_cleanup" afterward.
    struct AranyaAqcConfig aqc_cfg;
    err = aranya_aqc_config_build(&aqc_builder, &aqc_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "error initializing AQC config\n");
        return err;
    }

    struct AranyaClientConfigBuilder cli_builder;
    err = aranya_client_config_builder_init(&cli_builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to initialize `AranyaClientConfigBuilder`\n");
        aranya_client_config_builder_cleanup(&cli_builder);
        return err;
    }
    err = aranya_client_config_builder_set_daemon_uds_path(&cli_builder,
                                                           daemon_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to set daemon UDS path\n");
        aranya_client_config_builder_cleanup(&cli_builder);
        return err;
    }
    err = aranya_client_config_builder_set_daemon_api_pk(&cli_builder, api_pk,
                                                         api_pk_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to set daemon API public key\n");
        aranya_client_config_builder_cleanup(&cli_builder);
        return err;
    }

    err = aranya_client_config_builder_set_aqc_config(&cli_builder, &aqc_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to set daemon API public key\n");
        aranya_client_config_builder_cleanup(&cli_builder);
        return err;
    }

    // NB: A builder's "_build" method consumes the builder, so
    // do _not_ call "_cleanup" afterward.
    struct AranyaClientConfig cli_cfg;
    err = aranya_client_config_build(&cli_builder, &cli_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "error initializing client config: %s\n",
                aranya_error_to_str(err));
        return err;
    }

    err = aranya_client_init(&c->client, &cli_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "error initializing client %s (daemon_addr: %s)\n",
                c->name, daemon_addr);
        return err;
    }
    err = aranya_get_device_id(&c->client, &c->id);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to get device ID\n");
        aranya_client_cleanup(&c->client);
        return err;
    }

    // `pk_len` is intentionally set to small size to show how to
    // handle reallocations.
    c->pk_len = 1;
    c->pk     = malloc(c->pk_len);
    if (c->pk == NULL) {
        abort();
    }
    err = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        // Too small, so the actual size was written to
        // `c->pk_len`.
        uint8_t *new_pk = realloc(c->pk, c->pk_len);
        if (new_pk == NULL) {
            abort();
        }
        c->pk = new_pk;
        err   = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    }
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to get device IDs\n");
        aranya_client_cleanup(&c->client);
        return err;
    }

    return ARANYA_ERROR_SUCCESS;
}

// Initialize the Aranya `Team` by first initializing the team's clients and
// then creates the team.
AranyaError init_team(Team *t) {
    AranyaError err;

    // initialize team clients.
    for (int i = 0; i < NUM_CLIENTS; i++) {
        printf("initializing client: %s\n", client_names[i]);

        uint8_t *api_pk   = NULL;
        size_t api_pk_len = 0;
        err               = read_api_pk(&api_pk, &api_pk_len, client_names[i]);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "unable to read public API key\n");
            return err;
        }

        Client *client = &t->clients_arr[i];
        err = init_client(client, client_names[i], daemon_socks[i], api_pk,
                          api_pk_len, aqc_addrs[i]);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "unable to initialize client %s: %s\n",
                    client->name, aranya_error_to_str(err));
            free(api_pk);
            return err;
        }
        free(api_pk);
    }

    AranyaTeamConfigBuilder build;
    err = aranya_team_config_builder_init(&build);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to init `AranyaTeamConfigBuilder`\n");
        return err;
    }

    // NB: A builder's "_build" method consumes the builder, so
    // do _not_ call "_cleanup" afterward.
    AranyaTeamConfig cfg;
    err = aranya_team_config_build(&build, &cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to init `AranyaTeamConfigBuilder`\n");
        return err;
    }

    // have owner create the team.
    // The `aranya_create_team` method is used to create a new graph for the
    // team to operate on.
    AranyaTeamConfigBuilder build_2;
    AranyaTeamConfig cfg_2;

    err = aranya_team_config_builder_init(&build_2);
    EXPECT("error initialzing the team config builder", err);
    err = aranya_team_config_build(&build_2, &cfg_2);
    EXPECT("error building a team config", err);

    t->init_cmd_len = 1;
    t->init_cmd     = calloc(t->init_cmd_len, t->init_cmd_len);
    
    err = aranya_create_team(&t->clients.owner.client, &cfg_2, &t->id, t->init_cmd, &t->init_cmd_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("reallocating init command buffer\r\n");
        t->init_cmd = realloc(t->init_cmd, t->init_cmd_len);
        err = aranya_create_team(&t->clients.owner.client, &cfg_2, &t->id, t->init_cmd, &t->init_cmd_len);
    }
    EXPECT("error creating team", err);

    // Test ID serialization and deserialization
    char team_id_str[ARANYA_ID_STR_LEN] = {0};
    size_t team_id_str_len              = sizeof(team_id_str);
    err = aranya_id_to_str(&t->id.id, team_id_str, &team_id_str_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to convert ID to string\n");
        return err;
    }
    printf("Team ID: %s \n", team_id_str);

    AranyaId decodedId;
    err = aranya_id_from_str(team_id_str, &decodedId);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to decode ID from string\n");
        return err;
    }

    if (memcmp(decodedId.bytes, t->id.id.bytes, ARANYA_ID_LEN) != 0) {
        fprintf(stderr, "application failed: Decoded ID doesn't match\n");
        return ARANYA_ERROR_OTHER;
    }

exit:
    return err;
}

// Cleanup Aranya `Team`.
AranyaError cleanup_team(Team *t) {
    AranyaError err;
    AranyaError retErr = ARANYA_ERROR_SUCCESS;

    for (int i = 0; i < NUM_CLIENTS; i++) {
        free(t->clients_arr[i].pk);
        err = aranya_client_cleanup(&t->clients_arr[i].client);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "error cleaning up %s: %s\n",
                    t->clients_arr[i].name, aranya_error_to_str(err));
            retErr = err;
        }
    }
    return retErr;
}

// Add sync peers.
// This creates a complete graph where each Aranya client can sync with all
// the other Aranya client peers on the network.
AranyaError add_sync_peers(Team *t, AranyaSyncPeerConfig *cfg) {
    AranyaError err;

    for (int i = 0; i < NUM_CLIENTS; i++) {
        for (int j = 0; j < NUM_CLIENTS; j++) {
            if (i == j) {
                continue; // don't add self as a sync peer.
            }
            printf("adding sync peer %s to %s\n", t->clients_arr[j].name,
                   t->clients_arr[i].name);
            err = aranya_add_sync_peer(&t->clients_arr[i].client, &t->id,
                                       sync_addrs[j], cfg);
            if (err != ARANYA_ERROR_SUCCESS) {
                fprintf(stderr, "error adding sync peer %s to %s: %s\n",
                        t->clients_arr[j].name, t->clients_arr[i].name,
                        aranya_error_to_str(err));
                return err;
            }
        }
    }

    return ARANYA_ERROR_SUCCESS;
}

AranyaError add_team_to_devices(Team* t) {
    AranyaError err;

    AranyaTeamConfigBuilder build;
    AranyaTeamConfig cfg;

    err = aranya_team_config_builder_init(&build);
    EXPECT("error initialzing the team config builder", err);

    err = aranya_team_config_builder_init_command(&build, t->init_cmd, t->init_cmd_len);
    EXPECT("error setting the init command on the team config builder", err);

    err = aranya_team_config_build(&build, &cfg);
    EXPECT("error building a team config", err);

    // Storage exists due to a prior call to `sync_now`
    // err = aranya_add_team(&t->clients.admin.client, &t->id, &cfg);
    // EXPECT("error adding team for admin", err);
    err = aranya_add_team(&t->clients.operator.client, &t->id, &cfg);
    EXPECT("error adding team for operator", err);
    err = aranya_add_team(&t->clients.membera.client, &t->id, &cfg);
    EXPECT("error adding team for membera", err);
    err = aranya_add_team(&t->clients.memberb.client, &t->id, &cfg);
    EXPECT("error adding team for memberb", err);

    return ARANYA_ERROR_SUCCESS;
exit:
    return err;
}

// Run the example.
AranyaError run(Team *t) {
    AranyaError err;
    AranyaDeviceId *devices = NULL;
    Client *owner = &t->clients.owner;
    Client *admin = &t->clients.admin;
    Client *operator= &t->clients.operator;

    // initialize logging.
    printf("initializing logging\n");
    err = aranya_init_logging();
    EXPECT("error initializing logging", err);

    // initialize the Aranya team.
    printf("initializing team\n");
    err = init_team(t);
    EXPECT("unable to initialize team", err);

    // add admin to team.
    err =
        aranya_add_device_to_team(&owner->client, &t->id,
                                  admin->pk, admin->pk_len);
    EXPECT("error adding admin to team", err);

    // add operator to team.
    err = aranya_add_device_to_team(&owner->client, &t->id,
                                    operator->pk,
                                    operator->pk_len);
    EXPECT("error adding operator to team", err);

    // upgrade role to admin.
    err = aranya_assign_role(&owner->client, &t->id,
                             &admin->id, ARANYA_ROLE_ADMIN);
    EXPECT("error assigning admin role", err);

    // upgrade role to operator.
    err = aranya_assign_role(&admin->client, &t->id,
                             &operator->id, ARANYA_ROLE_OPERATOR);
    if (err == ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "application failed: expected role assignment to fail");
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }

    err = aranya_sync_now(&admin->client, &t->id, sync_addrs[OWNER],
                          NULL);
    EXPECT("error calling `sync_now` to sync with peer", err);

    sleep(1);
    err = aranya_assign_role(&admin->client, &t->id,
                             &operator->id, ARANYA_ROLE_OPERATOR);
    EXPECT("error assigning operator role", err);

    // Add teams to each device's local store
    // err = add_team_to_devices(t);
    // EXPECT("error adding team to devices", err);

    // Initialize the builder
    struct AranyaSyncPeerConfigBuilder builder;
    err = aranya_sync_peer_config_builder_init(&builder);
    EXPECT("error initializing sync peer config builder", err);

    // Set duration on the config builder
    AranyaDuration interval = ARANYA_DURATION_MILLISECONDS * 100;
    err = aranya_sync_peer_config_builder_set_interval(&builder, interval);
    EXPECT("error setting duration on config builder", err);

    // Set syncing to happen immediately on the config builder
    err = aranya_sync_peer_config_builder_set_sync_now(&builder);
    EXPECT("error setting `sync_now` on config builder", err);

    // Build the sync config
    struct AranyaSyncPeerConfig cfg;
    err = aranya_sync_peer_config_build(&builder, &cfg);
    EXPECT("error building the sync peer config", err);

    err = aranya_sync_peer_config_builder_cleanup(&builder);
    EXPECT("error running the cleanup routine for the config builder", err);

    // add sync peers.
    printf("adding sync peers\n");
    err = add_sync_peers(t, &cfg);
    EXPECT("error adding sync peers", err);

    // Team members are added to the team by first calling
    // `aranya_add_device_to_team`, passing in the submitter's client, the
    // team ID and the public key of the device to be added. In a real world
    // scenario, the keys would be exchanged outside of Aranya using
    // something like `scp`.

    // add membera to team.
    err = aranya_add_device_to_team(&owner->client, &t->id,
                                    t->clients.membera.pk,
                                    t->clients.membera.pk_len);
    EXPECT("error adding membera to team", err);

    // add memberb to team.
    err = aranya_add_device_to_team(&owner->client, &t->id,
                                    t->clients.memberb.pk,
                                    t->clients.memberb.pk_len);
    EXPECT("error adding memberb to team", err);

    sleep(1);

    // assign AQC network addresses.
    err = aranya_aqc_assign_net_identifier(&operator->client, &t->id,
                                           &t->clients.membera.id,
                                           aqc_addrs[MEMBERA]);
    EXPECT("error assigning aqc net name to membera", err);

    err = aranya_aqc_assign_net_identifier(&operator->client, &t->id,
                                           &t->clients.memberb.id,
                                           aqc_addrs[MEMBERB]);
    EXPECT("error assigning aqc net name to memberb", err);

    sleep(1);

    // Queries
    printf("running factdb queries\n");

    size_t devices_len = 256;
    devices            = calloc(devices_len, sizeof(AranyaDeviceId));
    if (devices == NULL) {
        abort();
    }
    err = aranya_query_devices_on_team(&operator->client, &t->id,
                                       devices, &devices_len);
    EXPECT("error querying devices on team", err);

    for (size_t i = 0; i < devices_len; i++) {
        AranyaDeviceId device_id = devices[i];

        char device_str[ARANYA_ID_STR_LEN] = {0};
        size_t device_str_len              = sizeof(device_str);
        err = aranya_id_to_str(&device_id.id, device_str, &device_str_len);
        EXPECT("unable to convert ID to string", err);

        printf("device_id: %s at index: %zu/%zu \n", device_str, i,
               devices_len);

        AranyaId decoded_id;
        err = aranya_id_from_str(device_str, &decoded_id);
        EXPECT("unable to decode ID", err);

        if (memcmp(decoded_id.bytes, device_id.id.bytes, ARANYA_ID_LEN) != 0) {
            fprintf(stderr, "application failed: Decoded ID doesn't match\n");
            err = ARANYA_ERROR_OTHER;
            goto exit;
        }
    }

    uint8_t memberb_keybundle[256] = {0};
    size_t memberb_keybundle_len   = sizeof(memberb_keybundle);
    err                            = aranya_query_device_keybundle(
        &operator->client, &t->id, &t->clients.memberb.id,
        memberb_keybundle, &memberb_keybundle_len);
    EXPECT("error querying memberb key bundle", err);
    printf(
        "%s key bundle len: %zu"
        "\n",
        t->clients_arr[MEMBERB].name, memberb_keybundle_len);

    // Query memberb's net identifier.
    char memberb_aqc_net_identifier[BUFFER_LEN] = {0};
    size_t memberb_aqc_net_identifier_len = sizeof(memberb_aqc_net_identifier);
    bool aqc_net_identifier_exists        = false;
    err                                   = aranya_query_aqc_net_identifier(
        &operator->client, &t->id, &t->clients.memberb.id,
        memberb_aqc_net_identifier, &memberb_aqc_net_identifier_len,
        &aqc_net_identifier_exists);
    EXPECT("error querying memberb aqc net identifier", err);
    if (!aqc_net_identifier_exists) {
        fprintf(stderr, "expected `memberb` to have an AQC net identifier\n");
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }
    printf("%s aqc net identifier: %s \n", t->clients_arr[MEMBERB].name,
           memberb_aqc_net_identifier);

    // Remove the net identifier.
    err = aranya_aqc_remove_net_identifier(&operator->client, &t->id,
                                           &t->clients.memberb.id,
                                           aqc_addrs[MEMBERB]);
    EXPECT("error removing memberb aqc net identifier", err);
    printf("removed aqc net identifier `%s` from `%s`\n",
           memberb_aqc_net_identifier, t->clients_arr[MEMBERB].name);

    // The net identifier should no longer exist.
    memberb_aqc_net_identifier_len = sizeof(memberb_aqc_net_identifier);
    err                            = aranya_query_aqc_net_identifier(
        &operator->client, &t->id, &t->clients.memberb.id,
        memberb_aqc_net_identifier, &memberb_aqc_net_identifier_len,
        &aqc_net_identifier_exists);
    EXPECT("error querying memberb aqc net identifier", err);
    if (aqc_net_identifier_exists) {
        fprintf(stderr, "`memberb` should no longer have a net identifier\n");
        err = ARANYA_ERROR_OTHER;
        goto exit;
    }

    // Add the net identifier back.
    err = aranya_aqc_assign_net_identifier(&operator->client, &t->id,
                                           &t->clients.memberb.id,
                                           aqc_addrs[MEMBERB]);
    EXPECT("error assigning aqc net name to memberb", err);

    err = run_aqc_example(t);
    EXPECT("error running aqc example", err);

exit:
    free(devices);
    return err;
}

// Run the AQC example.
AranyaError run_aqc_example(Team *t) {
    AranyaError err       = ARANYA_ERROR_OTHER;
    AranyaLabelId *labels = NULL;
    Client *admin = &t->clients.admin;
    Client *operator= &t->clients.operator;

    printf("running AQC demo \n");

    // Create label and assign it to members
    printf("creating labels\n");

    const char *label1_name = "label1";
    AranyaLabelId label1_id;
    err = aranya_create_label(&operator->client, &t->id, label1_name,
                              &label1_id);
    EXPECT("error creating label1", err);

    const char *label2_name = "label2";
    AranyaLabelId label2_id;
    err = aranya_create_label(&operator->client, &t->id, label2_name,
                              &label2_id);
    EXPECT("error creating label2", err);

    printf("assigning label to members\n");
    AranyaChanOp op = ARANYA_CHAN_OP_SEND_RECV;
    err             = aranya_assign_label(&operator->client, &t->id,
                                          &t->clients.membera.id, &label1_id, op);
    EXPECT("error assigning label1 to membera", err);

    err = aranya_assign_label(&operator->client, &t->id,
                              &t->clients.memberb.id, &label1_id, op);
    EXPECT("error assigning label2 to memberb", err);

    err = aranya_assign_label(&operator->client, &t->id,
                              &t->clients.membera.id, &label2_id, op);
    EXPECT("error assigning label2 to membera", err);

    err = aranya_assign_label(&operator->client, &t->id,
                              &t->clients.memberb.id, &label2_id, op);
    EXPECT("error assigning label2 to memberb", err);
    sleep(1);

    // Queries
    printf("query if label exists on team \n");
    bool exists = false;
    err         = aranya_query_label_exists(&t->clients.membera.client, &t->id,
                                            &label1_id, &exists);
    EXPECT("error querying label exists", err);
    printf("%s label exists: %s \n", t->clients_arr[MEMBERB].name,
           exists ? "true" : "false");

    char device_str[ARANYA_ID_STR_LEN] = {0};
    size_t device_str_len              = sizeof(device_str);
    err = aranya_id_to_str(&t->clients.memberb.id.id, device_str,
                           &device_str_len);
    EXPECT("unable to convert ID to string", err);
    printf("query labels assigned to device: %s\n", device_str);
    // `labels_len` is intentionally set to 1 when there are 2 labels to test
    // `ARANYA_ERROR_BUFFER_TOO_SMALL` error handling.
    size_t labels_len = 1;
    labels            = calloc(labels_len, sizeof(AranyaLabelId));
    if (labels == NULL) {
        abort();
    }
    err = aranya_query_device_label_assignments(&operator->client,
                                                &t->id, &t->clients.memberb.id,
                                                labels, &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("handling buffer too small error\n");
        labels = realloc(labels, labels_len * sizeof(AranyaLabelId));
        err = aranya_query_labels(&operator->client, &t->id, labels,
                                  &labels_len);
    }
    EXPECT("error querying labels assigned to device", err);

    for (size_t i = 0; i < labels_len; i++) {
        AranyaLabelId label_id            = labels[i];
        char label_str[ARANYA_ID_STR_LEN] = {0};
        size_t label_str_len              = sizeof(label_str);
        err = aranya_id_to_str(&label_id.id, label_str, &label_str_len);
        EXPECT("unable to convert ID to string", err);
        printf("label_id: %s at index: %zu/%zu \n", label_str, i, labels_len);
    }

    char team_str[ARANYA_ID_STR_LEN] = {0};
    size_t team_str_len              = sizeof(team_str);
    err = aranya_id_to_str(&t->id.id, team_str, &team_str_len);
    EXPECT("unable to convert ID to string", err);

    printf("query labels on team: %s\n", team_str);
    // `labels_len` is intentionally set to 1 when there are 2 labels to test
    // `ARANYA_ERROR_BUFFER_TOO_SMALL` error handling.
    labels_len = 1;
    err = aranya_query_labels(&operator->client, &t->id, labels,
                              &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("handling buffer too small error\n");
        labels = realloc(labels, labels_len * sizeof(AranyaLabelId));
        err = aranya_query_labels(&operator->client, &t->id, labels,
                                  &labels_len);
    }
    EXPECT("error querying labels on team", err);

    for (size_t i = 0; i < labels_len; i++) {
        AranyaLabelId label_id            = labels[i];
        char label_str[ARANYA_ID_STR_LEN] = {0};
        size_t label_str_len              = sizeof(label_str);
        err = aranya_id_to_str(&label_id.id, label_str, &label_str_len);
        EXPECT("unable to convert ID to string", err);
        printf("label_id: %s at index: %zu/%zu \n", label_str, i, labels_len);
    }

    // Create channel using Member A's client
    printf("creating AQC channel \n");
    AranyaAqcBidiChannelId chan_id;
    err = aranya_aqc_create_bidi_channel(&t->clients.membera.client, &t->id,
                                         aqc_addrs[MEMBERB], &label1_id,
                                         &chan_id);
    EXPECT("error creating aqc bidi channel", err);

    // TODO: send AQC data

    // Revoke/delete label using the Operator
    printf("revoke/delete label \n");
    err = aranya_revoke_label(&operator->client, &t->id,
                              &t->clients.membera.id, &label1_id);
    EXPECT("error revoking label from membera", err);
    err = aranya_revoke_label(&operator->client, &t->id,
                              &t->clients.memberb.id, &label1_id);
    EXPECT("error revoking label from memberb", err);
    err = aranya_delete_label(&admin->client, &t->id, &label1_id);
    EXPECT("error deleting label", err);

exit:
    free(labels);
    return err;
}

int main(void) {
    Team team;
    AranyaError err = ARANYA_ERROR_OTHER;
    int retErr      = EXIT_SUCCESS;

    // TODO: take work_dirs, shm_paths, daemon_socks, IP addresses as input?

    // run the example.
    err = run(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "application failed: %s\n", aranya_error_to_str(err));
        retErr = EXIT_FAILURE;
    }

    // cleanup team.
    printf("cleaning up the Aranya team \n");
    err = cleanup_team(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        retErr = EXIT_FAILURE;
    }

    return retErr;
}
