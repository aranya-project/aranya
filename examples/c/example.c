/*
 * Copyright (c) SpiderOak, Inc. All rights reserved.
 */
/**
 * @file example.c
 * @brief Example C application using the Aranya client library.
 */

// Note: this file is formatted with `clang-format`.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "aranya-client.h"

// Macro for printing AranyaError to stderr and returning the error.
// Does nothing if error value is ARANYA_SUCCESS.
#define EXPECT(M, E)                                                           \
    do {                                                                       \
        AranyaError error = (E);                                               \
        if (err != ARANYA_ERROR_SUCCESS) {                                     \
            fprintf(stderr, "%s: %s\r\n", (M), aranya_error_to_str(error));    \
            return error;                                                      \
        }                                                                      \
    } while (0)

// Macro for printing client AranyaError to stderr and returning the error.
// Does nothing if error value is ARANYA_SUCCESS.
#define CLIENT_EXPECT(M, N, E)                                                 \
    do {                                                                       \
        AranyaError error = (E);                                               \
        if (error != ARANYA_ERROR_SUCCESS) {                                   \
            fprintf(stderr, "%s %s: %s\r\n", (M), (N),                         \
                    aranya_error_to_str(error));                               \
            return error;                                                      \
        }                                                                      \
    } while (0)

// Size of data buffer.
#define BUF_LEN 256

// Number of clients on Aranya team.
#define NUM_CLIENTS 5

// Number of roles on Aranya team (excluding owner role).
#define NUM_ROLES 3

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
    union {
        struct {
            // Admin role.
            AranyaRoleId admin;
            // Operator role.
            AranyaRoleId operator;
            // Member role.
            AranyaRoleId member;
        } roles;
        AranyaRoleId roles_arr[NUM_ROLES];
    };
} Team;

AranyaError init_client(Client *c, const char *name, const char *daemon_addr,
                        const char *aqc_addr);
AranyaError init_team(Team *t);
AranyaError cleanup_team(Team *t);
AranyaError add_sync_peers(Team *t, AranyaSyncPeerConfig *cfg);
AranyaError run(Team *t);
AranyaError run_aqc_example(Team *t);
AranyaError init_roles(Team *t);
AranyaError cleanup_roles(Team *t);
AranyaError setup_default_roles(Team *t, AranyaRole **roles, size_t *roles_len);

// Query functions.
AranyaError query_devices_on_team(Team *t, AranyaDeviceId **devices,
                                  size_t *devices_len);
AranyaError query_roles_on_team(Team *t, AranyaRole **roles, size_t *roles_len);
AranyaError query_device_roles(Team *t, AranyaDeviceId *device,
                               AranyaRole **roles, size_t *roles_len);
AranyaError query_role_operations(Team *t, AranyaRoleId *role,
                                  AranyaOperation **ops, size_t *ops_len);

// Initialize an Aranya client.
AranyaError init_client(Client *c, const char *name, const char *daemon_addr,
                        const char *aqc_addr) {
    AranyaError err;
    c->name = name;

    struct AranyaClientConfigBuilder cli_build;
    struct AranyaClientConfig cli_cfg;
    err = aranya_client_config_builder_init(&cli_build);
    EXPECT("error initializing client config builder", err);
    aranya_client_config_builder_set_daemon_addr(&cli_build, daemon_addr);
    struct AranyaAqcConfigBuilder aqc_build;
    struct AranyaAqcConfig aqc_cfg;
    err = aranya_aqc_config_builder_init(&aqc_build);
    EXPECT("error initializing client config builder", err);
    aranya_aqc_config_builder_set_address(&aqc_build, aqc_addr);
    err = aranya_aqc_config_builder_build(&aqc_build, &aqc_cfg);

    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "error initializing config: %s\r\n",
                aranya_error_to_str(err));
        return err;
    }
    err = aranya_aqc_config_builder_cleanup(&aqc_build);
    EXPECT("error running the cleanup routine for the aqc config builder", err);

    aranya_client_config_builder_set_aqc_config(&cli_build, &aqc_cfg);

    err = aranya_client_config_builder_build(&cli_build, &cli_cfg);

    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "error initializing client config: %s\r\n",
                aranya_error_to_str(err));
        return err;
    }

    err = aranya_client_config_builder_cleanup(&cli_build);
    EXPECT("error running the cleanup routine for the client config builder",
           err);

    err = aranya_client_init(&c->client, &cli_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr,
                "error initializing client %s (daemon_addr: %s): %s\r\n",
                c->name, daemon_addr, aranya_error_to_str(err));
        return err;
    }
    err = aranya_get_device_id(&c->client, &c->id);
    CLIENT_EXPECT("error getting device id", c->name, err);

    c->pk_len = 8; // intentionally set to small size to show reallocation
    c->pk     = malloc(c->pk_len);
    err       = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("reallocating key bundle buffer\r\n");
        c->pk = realloc(c->pk, c->pk_len);
        err   = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    }
    CLIENT_EXPECT("error getting key bundle", c->name, err);

    return ARANYA_ERROR_SUCCESS;
}

// Initialize the Aranya `Team` by first initializing the team's clients and
// then creates the team.
AranyaError init_team(Team *t) {
    AranyaError err;

    // initialize team clients.
    for (int i = 0; i < NUM_CLIENTS; i++) {
        printf("initializing client: %s\r\n", client_names[i]);
        err = init_client(&t->clients_arr[i], client_names[i], daemon_socks[i],
                          aqc_addrs[i]);
        EXPECT("error initializing team", err);
    }

    // have owner create the team.
    // The `aranya_create_team` method is used to create a new graph for the
    // team to operate on.
    AranyaTeamConfigBuilder build;
    AranyaTeamConfig cfg;
    aranya_team_config_builder_build(&build, &cfg);
    err = aranya_create_team(&t->clients.owner.client, &cfg, &t->id);
    EXPECT("error creating team", err);

    // Test ID serialization and deserialization
    size_t team_id_str_len = ARANYA_ID_STR_LEN;
    char *team_id_str      = malloc(team_id_str_len);
    aranya_id_to_str(&t->id.id, team_id_str, &team_id_str_len);
    printf("Team ID: %s \r\n", team_id_str);

    AranyaId decodedId;
    err = aranya_id_from_str(team_id_str, &decodedId);
    EXPECT("error decoding string into an ID", err);

    free(team_id_str);

    if (!(memcmp(decodedId.bytes, t->id.id.bytes, ARANYA_ID_LEN) == 0)) {
        fprintf(stderr, "application failed: Decoded ID doesn't match\r\n");
        return EXIT_FAILURE;
    }

    return ARANYA_ERROR_SUCCESS;
}

// Cleanup Aranya `Team`.
AranyaError cleanup_team(Team *t) {
    AranyaError err;
    AranyaError retErr = ARANYA_ERROR_SUCCESS;

    for (int i = 0; i < NUM_CLIENTS; i++) {
        free(t->clients_arr[i].pk);
        err = aranya_client_cleanup(&t->clients_arr[i].client);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "error cleaning up %s: %s\r\n",
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
            printf("adding sync peer %s to %s\r\n", t->clients_arr[j].name,
                   t->clients_arr[i].name);
            err = aranya_add_sync_peer(&t->clients_arr[i].client, &t->id,
                                       sync_addrs[j], cfg);
            if (err != ARANYA_ERROR_SUCCESS) {
                fprintf(stderr, "error adding sync peer %s to %s: %s\r\n",
                        t->clients_arr[j].name, t->clients_arr[i].name,
                        aranya_error_to_str(err));
                return err;
            }
        }
    }

    return ARANYA_ERROR_SUCCESS;
}

// Run the example.
AranyaError run(Team *t) {
    AranyaError err;

    // initialize logging.
    printf("initializing logging\r\n");
    err = aranya_init_logging();
    EXPECT("error initializing logging", err);

    // initialize the Aranya team.
    printf("initializing team\r\n");
    err = init_team(t);
    EXPECT("error initializing team", err);

    err = init_roles(t);
    EXPECT("error initializing roles", err);

    // add admin to team.
    AranyaDevicePrecedence precedence = 9000;
    err =
        aranya_add_device_to_team(&t->clients.owner.client, &t->id, &precedence,
                                  t->clients.admin.pk, t->clients.admin.pk_len);
    EXPECT("error adding admin to team", err);
    precedence = 8500;
    err = aranya_assign_device_precedence(&t->clients.owner.client, &t->id,
                                          &t->clients.admin.id, &precedence);
    EXPECT("error assigning new device precedence to admin", err);

    // add operator to team.
    precedence = 8000;
    err        = aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                           &precedence, t->clients.operator.pk,
                                           t->clients.operator.pk_len);
    EXPECT("error adding operator to team", err);

    // upgrade role to admin.
    err = aranya_assign_role(&t->clients.owner.client, &t->id,
                             &t->clients.admin.id, &t->roles.admin);
    EXPECT("error assigning admin role", err);

    // upgrade role to operator.
    err = aranya_assign_role(&t->clients.owner.client, &t->id,
                             &t->clients.operator.id, &t->roles.operator);

    // TODO: add sync now test back

    sleep(1);
    err = aranya_assign_role(&t->clients.owner.client, &t->id,
                             &t->clients.operator.id, &t->roles.operator);
    EXPECT("error assigning operator role", err);

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
    err = aranya_sync_peer_config_builder_build(&builder, &cfg);
    EXPECT("error building the sync peer config", err);

    err = aranya_sync_peer_config_builder_cleanup(&builder);
    EXPECT("error running the cleanup routine for the config builder", err);

    // add sync peers.
    printf("adding sync peers\r\n");
    err = add_sync_peers(t, &cfg);
    EXPECT("error adding sync peers", err);

    // Team members are added to the team by first calling
    // `aranya_add_device_to_team`, passing in the submitter's client, the
    // team ID and the public key of the device to be added. In a real world
    // scenario, the keys would be exchanged outside of Aranya using
    // something like `scp`.

    // add membera to team.
    precedence = 7000;
    err        = aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                           &precedence, t->clients.membera.pk,
                                           t->clients.membera.pk_len);
    EXPECT("error adding membera to team", err);
    err = aranya_assign_role(&t->clients.owner.client, &t->id,
                             &t->clients.membera.id, &t->roles.member);
    EXPECT("error assigning membera the member role", err);

    // add memberb to team.
    err = aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                    &precedence, t->clients.memberb.pk,
                                    t->clients.memberb.pk_len);
    EXPECT("error adding memberb to team", err);
    err = aranya_assign_role(&t->clients.owner.client, &t->id,
                             &t->clients.memberb.id, &t->roles.member);
    EXPECT("error assigning memberb the member role", err);

    sleep(1);

    // assign AQC network addresses.
    err = aranya_aqc_assign_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.membera.id,
                                           aqc_addrs[MEMBERA]);
    EXPECT("error assigning aqc net name to membera", err);

    err = aranya_aqc_assign_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.memberb.id,
                                           aqc_addrs[MEMBERB]);
    EXPECT("error assigning aqc net name to memberb", err);

    sleep(1);

    // Queries
    printf("running factdb queries\r\n");
    printf("querying devices on team\r\n");

    size_t devices_len      = 0;
    AranyaDeviceId *devices = NULL;
    err                     = query_devices_on_team(t, &devices, &devices_len);
    EXPECT("error querying devices on team", err);

    for (size_t i = 0; i < devices_len; i++) {
        AranyaDeviceId device_result = devices[i];
        size_t device_str_len        = ARANYA_ID_STR_LEN;
        char *device_str             = malloc(ARANYA_ID_STR_LEN);
        aranya_id_to_str(&device_result.id, device_str, &device_str_len);
        printf("device_id: %s at index: %zu/%zu \r\n", device_str, i,
               devices_len);

        AranyaId decodedId;
        err = aranya_id_from_str(device_str, &decodedId);
        EXPECT("error decoding string into an ID", err);

        free(device_str);

        if (!(memcmp(decodedId.bytes, device_result.id.bytes, ARANYA_ID_LEN) ==
              0)) {
            fprintf(stderr, "application failed: Decoded ID doesn't match\r\n");
            return EXIT_FAILURE;
        }
    }
    free(devices);

    printf("querying roles on team\r\n");
    size_t roles_len  = BUF_LEN;
    AranyaRole *roles = malloc(roles_len * sizeof(AranyaRole));
    err = aranya_query_roles_on_team(&t->clients.operator.client, &t->id, roles,
                                     &roles_len);
    EXPECT("error querying roles on team", err);
    if (roles == NULL) {
        return ARANYA_ERROR_BUG;
    }
    printf("found %zu roles on team\r\n", roles_len);
    for (size_t i = 0; i < roles_len; i++) {
        AranyaRole role_result = roles[i];
        const char *role_str   = NULL;
        err                    = aranya_role_get_name(&role_result, &role_str);
        EXPECT("unable to get role name", err);
        printf("role: %s at index: %zu/%zu \r\n", role_str, i, roles_len);
        err = aranya_role_cleanup(&roles[i]);
        EXPECT("unable to cleanup role", err);
    }
    free(roles);

    size_t device_roles_len  = 0;
    AranyaRole *device_roles = NULL;
    err = query_device_roles(t, &t->clients.admin.id, &device_roles,
                             &device_roles_len);
    EXPECT("error querying device roles", err);

    for (size_t i = 0; i < device_roles_len; i++) {
        AranyaRole role_result = device_roles[i];
        const char *role_str   = NULL;
        err                    = aranya_role_get_name(&role_result, &role_str);
        EXPECT("unable to get role name", err);
        printf("role: %s at index: %zu/%zu \r\n", role_str, i,
               device_roles_len);
        err = aranya_role_cleanup(&device_roles[i]);
        EXPECT("unable to cleanup role", err);
    }
    free(device_roles);

    printf("querying admin role permissions\r\n");
    size_t ops_len       = BUF_LEN;
    AranyaOperation *ops = malloc(ops_len * sizeof(AranyaOperation));
    err = aranya_query_role_operations(&t->clients.operator.client, &t->id,
                                       &t->roles.admin, ops, &ops_len);
    EXPECT("error querying role ops", err);
    if (roles == NULL) {
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < ops_len; i++) {
        AranyaOperation op_result = ops[i];
        size_t op_str_len         = 255;
        char *op_str              = malloc(op_str_len);
        err = aranya_op_to_str(&op_result, op_str, &op_str_len);
        EXPECT("unable to get op name", err);
        printf("op: %s at index: %zu/%zu \r\n", op_str, i, ops_len);
        free(op_str);
    }
    free(ops);

    size_t memberb_keybundle_len = 255;
    uint8_t *memberb_keybundle   = malloc(memberb_keybundle_len);
    err                          = aranya_query_device_keybundle(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id,
        memberb_keybundle, &memberb_keybundle_len);
    EXPECT("error querying memberb key bundle", err);
    printf(
        "%s key bundle len: %zu"
        "\r\n",
        t->clients_arr[MEMBERB].name, memberb_keybundle_len);

    size_t memberb_aqc_net_identifier_len = BUF_LEN;
    char *memberb_aqc_net_identifier      = malloc(BUF_LEN);
    bool aqc_net_identifier_exists        = false;
    err                                   = aranya_query_aqc_net_identifier(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id,
        memberb_aqc_net_identifier, &memberb_aqc_net_identifier_len,
        &aqc_net_identifier_exists);
    EXPECT("error querying memberb aqc net identifier", err);
    if (!aqc_net_identifier_exists) {
        fprintf(stderr, "expected AQC net identifier to be returned\r\n");
        return ARANYA_ERROR_BUG;
    }
    printf("%s aqc net identifier: %s \r\n", t->clients_arr[MEMBERB].name,
           memberb_aqc_net_identifier);

    err = aranya_aqc_remove_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.memberb.id,
                                           aqc_addrs[MEMBERB]);
    EXPECT("error removing memberb aqc net identifier", err);
    printf("%s removed aqc net identifier: %s \r\n",
           t->clients_arr[MEMBERB].name, memberb_aqc_net_identifier);
    memberb_aqc_net_identifier_len = BUF_LEN;
    err                            = aranya_query_aqc_net_identifier(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id,
        memberb_aqc_net_identifier, &memberb_aqc_net_identifier_len,
        &aqc_net_identifier_exists);
    EXPECT("error querying memberb aqc net identifier", err);
    if (aqc_net_identifier_exists) {
        fprintf(stderr, "did not expect AQC net identifier to be returned\r\n");
        return ARANYA_ERROR_BUG;
    }
    printf("%s aqc net identifier: %s \r\n", t->clients_arr[MEMBERB].name,
           memberb_aqc_net_identifier);
    free(memberb_aqc_net_identifier);

    err = run_aqc_example(t);
    EXPECT("error running aqc example", err);

    err = cleanup_roles(t);
    EXPECT("error cleaning up roles", err);

    return ARANYA_ERROR_SUCCESS;
}

// Run the AQC example.
AranyaError run_aqc_example(Team *t) {
    AranyaError err;

    printf("running AQC demo \r\n");

    // Create label1 and assign it to members
    printf("creating label \r\n");
    const char *label1_name = "label1";
    AranyaLabel label1;
    err = aranya_create_label(&t->clients.operator.client, &t->id, label1_name,
                              &label1);
    EXPECT("error creating label1", err);
    AranyaLabelId label1_id;
    err = aranya_label_get_id(&label1, &label1_id);
    EXPECT("error getting label1 ID", err);
    const char *label1_str = NULL;
    err                    = aranya_label_get_name(&label1, &label1_str);
    EXPECT("error getting label1 name", err);
    printf("label1 name: %s \r\n", label1_str);

    // Create label2 and assign it to members
    const char *label2_name = "label2";
    AranyaLabel label2;
    err = aranya_create_label(&t->clients.operator.client, &t->id, label2_name,
                              &label2);
    EXPECT("error creating label2", err);
    AranyaLabelId label2_id;
    err = aranya_label_get_id(&label2, &label2_id);
    EXPECT("error getting label2 ID", err);
    const char *label2_str = NULL;
    err                    = aranya_label_get_name(&label2, &label2_str);
    EXPECT("error getting label2 name", err);
    printf("label2 name: %s \r\n", label2_str);
    printf("assigning label to members \r\n");
    AranyaChanOp op = ARANYA_CHAN_OP_SEND_RECV;
    err             = aranya_assign_label(&t->clients.operator.client, &t->id,
                                          &t->clients.membera.id, &label1_id, op);
    EXPECT("error assigning label1 to membera", err);
    err = aranya_assign_label(&t->clients.operator.client, &t->id,
                              &t->clients.memberb.id, &label1_id, op);
    EXPECT("error assigning label2 to memberb", err);
    err = aranya_assign_label(&t->clients.operator.client, &t->id,
                              &t->clients.membera.id, &label2_id, op);
    EXPECT("error assigning label2 to membera", err);
    err = aranya_assign_label(&t->clients.operator.client, &t->id,
                              &t->clients.memberb.id, &label2_id, op);
    EXPECT("error assigning label2 to memberb", err);
    sleep(1);

    // Queries
    printf("query if label exists on team \r\n");
    bool exists = false;
    err         = aranya_query_label_exists(&t->clients.membera.client, &t->id,
                                            &label1_id, &exists);
    EXPECT("error querying label exists", err);
    printf("%s label exists: %s \r\n", t->clients_arr[MEMBERB].name,
           exists ? "true" : "false");

    size_t device_str_len = ARANYA_ID_STR_LEN;
    char *device_str      = malloc(ARANYA_ID_STR_LEN);
    aranya_id_to_str(&t->clients.memberb.id.id, device_str, &device_str_len);
    printf("query labels assigned to device: %s\r\n", device_str);
    // `labels_len` is intentionally set to 1 when there are 2 labels to test
    // `ARANYA_ERROR_BUFFER_TOO_SMALL` error handling.
    size_t labels_len   = 1;
    AranyaLabel *labels = malloc(labels_len * sizeof(AranyaLabel));
    err = aranya_query_device_label_assignments(&t->clients.operator.client,
                                                &t->id, &t->clients.memberb.id,
                                                labels, &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("handling buffer too small error\r\n");
        labels = realloc(labels, labels_len * sizeof(AranyaLabel));
        err = aranya_query_labels(&t->clients.operator.client, &t->id, labels,
                                  &labels_len);
    }
    EXPECT("error querying labels assigned to device", err);
    if (labels == NULL) {
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < labels_len; i++) {
        AranyaLabel label_result = labels[i];
        const char *label_str    = NULL;
        aranya_label_get_name(&label_result, &label_str);
        printf("label: %s at index: %zu/%zu \r\n", label_str, i, labels_len);
    }
    free(device_str);

    size_t team_str_len = ARANYA_ID_STR_LEN;
    char *team_str      = malloc(ARANYA_ID_STR_LEN);
    aranya_id_to_str(&t->id.id, team_str, &team_str_len);
    printf("query labels on team: %s\r\n", team_str);
    // `labels_len` is intentionally set to 1 when there are 2 labels to test
    // `ARANYA_ERROR_BUFFER_TOO_SMALL` error handling.
    labels_len = 1;
    err = aranya_query_labels(&t->clients.operator.client, &t->id, labels,
                              &labels_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("handling buffer too small error\r\n");
        labels = realloc(labels, labels_len * sizeof(AranyaLabel));
        err = aranya_query_labels(&t->clients.operator.client, &t->id, labels,
                                  &labels_len);
    }
    EXPECT("error querying labels on team", err);
    if (labels == NULL) {
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < labels_len; i++) {
        AranyaLabel label_result = labels[i];
        const char *label_str    = NULL;
        aranya_label_get_name(&label_result, &label_str);
        printf("label: %s at index: %zu/%zu \r\n", label_str, i, labels_len);
        err = aranya_label_cleanup(&labels[i]);
        EXPECT("unable to cleanup label", err);
    }
    free(labels);
    free(team_str);

    // Create channel using Member A's client
    printf("creating AQC channel \r\n");
    AranyaAqcBidiChannelId chan_id;
    err = aranya_aqc_create_bidi_channel(&t->clients.membera.client, &t->id,
                                         aqc_addrs[MEMBERB], &label1_id,
                                         &chan_id);
    EXPECT("error creating aqc bidi channel", err);

    // TODO: send AQC data

    // Revoke/delete label using the Operator
    printf("revoke/delete label \r\n");
    err = aranya_revoke_label(&t->clients.operator.client, &t->id,
                              &t->clients.membera.id, &label1_id);
    EXPECT("error revoking label from membera", err);
    err = aranya_revoke_label(&t->clients.operator.client, &t->id,
                              &t->clients.memberb.id, &label1_id);
    EXPECT("error revoking label from memberb", err);

    // TODO: delete label.

    return err;
}

AranyaError init_roles(Team *t) {
    AranyaError err;

    printf("initializing roles\r\n");

    // Create default roles.
    size_t roles_len  = 0;
    AranyaRole *roles = NULL;
    err               = setup_default_roles(t, &roles, &roles_len);

    if (roles_len != 3) {
        for (size_t i = 0; i < roles_len; i++) {
            err = aranya_role_cleanup(&roles[i]);
            EXPECT("unable to cleanup role", err);
        }
        free(roles);
        fprintf(stderr,
                "expected 3 default roles: admin, operator, member\r\n");
        return ARANYA_ERROR_BUG;
    }
    for (size_t i = 0; i < roles_len; i++) {
        AranyaRoleId role_id;
        err = aranya_role_get_id(&roles[i], &role_id);
        EXPECT("error getting role ID", err);
        const char *role_str;
        err = aranya_role_get_name(&roles[i], &role_str);
        printf("setup role: %s\r\n", role_str);
        if (!strncmp("admin", role_str, strnlen(role_str, 255))) {
            t->roles.admin = role_id;
        }
        if (!strncmp("operator", role_str, strnlen(role_str, 255))) {
            t->roles.operator= role_id;
        }
        if (!strncmp("member", role_str, strnlen(role_str, 255))) {
            t->roles.member = role_id;
        }
        err = aranya_role_cleanup(&roles[i]);
        EXPECT("unable to cleanup role", err);
    }
    free(roles);

    // create a dummy role.
    AranyaRole role;
    err = aranya_create_role(&t->clients.owner.client, &t->id, "dummy", &role);
    EXPECT("expected to be able to create role", err);
    AranyaRoleId role_id;
    err = aranya_role_get_id(&role, &role_id);
    EXPECT("error getting dummy role id", err);

    // assign an operation to admin.
    err = aranya_assign_operation_to_role(&t->clients.owner.client, &t->id,
                                          &t->roles.admin,
                                          ARANYA_OP_DELETE_LABEL);
    EXPECT("error assigning delete label op to admin", err);

    return err;
}

AranyaError cleanup_roles(Team *t) {
    AranyaError err;

    printf("cleaning up roles\r\n");

    AranyaRoleId owner_role_id;
    size_t devices_len      = 0;
    AranyaDeviceId *devices = NULL;
    err                     = query_devices_on_team(t, &devices, &devices_len);
    EXPECT("error querying devices on team", err);

    for (size_t i = 0; i < devices_len; i++) {
        size_t roles_len  = 0;
        AranyaRole *roles = NULL;
        err = query_device_roles(t, &devices[i], &roles, &roles_len);
        EXPECT("error querying device roles", err);
        for (size_t j = 0; j < roles_len; j++) {
            AranyaRoleId role_id;
            err = aranya_role_get_id(&roles[j], &role_id);
            if (!memcmp(&t->clients.owner.id, &devices[i],
                        sizeof(AranyaDeviceId))) {
                owner_role_id = role_id;
            } else {
                const char *role_str;
                err = aranya_role_get_name(&roles[j], &role_str);
                printf("revoking role: %s\r\n", role_str);

                EXPECT("error getting role ID", err);
                err = aranya_revoke_role(&t->clients.owner.client, &t->id,
                                         &devices[i], &role_id);
                EXPECT("error revoking role", err);
            }
            err = aranya_role_cleanup(&roles[j]);
            EXPECT("unable to cleanup role", err);
        }
        free(roles);
    }
    free(devices);

    // Revoke operation permissions from roles.
    size_t roles_len  = 0;
    AranyaRole *roles = NULL;
    err               = query_roles_on_team(t, &roles, &roles_len);
    EXPECT("error querying roles on team", err);

    for (size_t i = 0; i < roles_len; i++) {
        AranyaRoleId role_id;
        err = aranya_role_get_id(&roles[i], &role_id);
        EXPECT("error getting role ID", err);
        const char *role_str;
        err = aranya_role_get_name(&roles[i], &role_str);
        printf("revoking ops for role: %s\r\n", role_str);

        size_t ops_len       = 0;
        AranyaOperation *ops = NULL;
        err = query_role_operations(t, &role_id, &ops, &ops_len);
        printf("ops_len: %zu\r\n", ops_len);
        EXPECT("error querying role permissions", err);
        for (size_t j = 0; j < ops_len; j++) {
            if (memcmp(&owner_role_id, &role_id, sizeof(AranyaRoleId))) {
                AranyaOp op;
                err = aranya_op_get_enum(&ops[j], &op);
                EXPECT("error getting operation enum", err);
                err = aranya_revoke_role_operation(&t->clients.owner.client,
                                                   &t->id, &role_id, op);
                EXPECT("error revoking role op", err);
                size_t op_str_len = 255;
                char *op_str      = malloc(op_str_len);
                err = aranya_op_to_str(&ops[j], op_str, &op_str_len);
                EXPECT("error getting op name", err);
                printf("revoked role op: %s\r\n", op_str);
                free(op_str);
            }
        }
        free(ops);
        err = aranya_role_cleanup(&roles[i]);
        EXPECT("unable to cleanup role", err);
    }
    free(roles);

    // TODO: delete roles.

    return err;
}

// Query devices on team. Returned `devices` ptr must be freed.
AranyaError query_devices_on_team(Team *t, AranyaDeviceId **devices,
                                  size_t *devices_len) {
    AranyaError err;

    *devices_len = BUF_LEN;
    *devices     = malloc(*devices_len * sizeof(AranyaDeviceId));
    err = aranya_query_devices_on_team(&t->clients.operator.client, &t->id,
                                       *devices, devices_len);
    EXPECT("error querying devices on team", err);
    if (devices == NULL) {
        return ARANYA_ERROR_BUG;
    }

    return err;
}

// Setup default roles on team. Returned `roles` ptr must be freed.
AranyaError setup_default_roles(Team *t, AranyaRole **roles,
                                size_t *roles_len) {
    AranyaError err;

    *roles_len = BUF_LEN;
    *roles     = malloc(*roles_len * sizeof(AranyaRole));
    err = aranya_setup_default_roles(&t->clients.owner.client, &t->id, *roles,
                                     roles_len);
    EXPECT("error setting up default roles on team", err);
    if (roles == NULL) {
        return ARANYA_ERROR_BUG;
    }

    return err;
}

// Query roles on team. Returned `roles` ptr must be freed.
AranyaError query_roles_on_team(Team *t, AranyaRole **roles,
                                size_t *roles_len) {
    AranyaError err;

    *roles_len = BUF_LEN;
    *roles     = malloc(*roles_len * sizeof(AranyaRole));
    err        = aranya_query_roles_on_team(&t->clients.operator.client, &t->id,
                                            *roles, roles_len);
    EXPECT("error querying roles on team", err);
    if (roles == NULL) {
        return ARANYA_ERROR_BUG;
    }

    return err;
}

// Query device roles. Returned `roles` ptr must be freed.
AranyaError query_device_roles(Team *t, AranyaDeviceId *device,
                               AranyaRole **roles, size_t *roles_len) {
    AranyaError err;

    *roles_len = BUF_LEN;
    *roles     = malloc(*roles_len * sizeof(**roles));
    err = aranya_query_device_roles(&t->clients.operator.client, &t->id, device,
                                    *roles, roles_len);
    EXPECT("error querying device roles", err);
    if (roles == NULL) {
        return ARANYA_ERROR_BUG;
    }

    return err;
}

// Query role permissions. Returned `ops` ptr must be freed.
AranyaError query_role_operations(Team *t, AranyaRoleId *role,
                                  AranyaOperation **ops, size_t *ops_len) {
    AranyaError err;

    *ops_len = BUF_LEN;
    *ops     = malloc(*ops_len * sizeof(AranyaOperation));
    err      = aranya_query_role_operations(&t->clients.operator.client, &t->id,
                                            role, *ops, ops_len);
    EXPECT("error querying role ops", err);
    if (ops == NULL) {
        return ARANYA_ERROR_BUG;
    }

    return err;
}

int main(void) {
    Team team;
    AranyaError err;
    int retErr = EXIT_SUCCESS;

    // TODO: take work_dirs, shm_paths, daemon_socks, IP addresses as input?

    // run the example.
    err = run(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "application failed: %s\r\n", aranya_error_to_str(err));
        retErr = EXIT_FAILURE;
    }

    // cleanup team.
    printf("cleaning up the Aranya team \r\n");
    err = cleanup_team(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        retErr = EXIT_FAILURE;
    }

    return retErr;
}
