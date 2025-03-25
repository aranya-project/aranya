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

// Maximum number of AFC channels supported by shared memory.
// This number must be configured the same for both the read and write
// sides.
#define MAX_CHANS 256

// Number of clients on Aranya team.
#define NUM_CLIENTS 5

// Team members enum. Can index into team member arrays.
typedef enum {
    OWNER,
    ADMIN,
    OPERATOR,
    MEMBERA,
    MEMBERB,
} Members;

// List of shared memory paths for the Aranya clients.
const char *shm_paths[] = {"/owner", "/admin", "/operator", "/membera",
                           "/memberb"};

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

// List of AFC addresses.
const AranyaNetIdentifier afc_addrs[] = {"127.0.0.1:11001", "127.0.0.1:11002",
                                         "127.0.0.1:11003", "127.0.0.1:11004",
                                         "127.0.0.1:11005"};

// Aranya client.
typedef struct {
    // Name of Aranya client.
    const char *name;
    // Pointer to Aranya client.
    AranyaClient client;
    // Aranya client's public key bundle.
    AranyaKeyBundle pk;
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
} Team;

AranyaError init_client(Client *c, const char *name, const char *daemon_sock,
                        const char *shm_path, const char *afc_addr);
AranyaError init_team(Team *t);
AranyaError add_sync_peers(Team *t);
AranyaError run(Team *t);
AranyaError cleanup_team(Team *t);

// Initialize an Aranya client.
AranyaError init_client(Client *c, const char *name, const char *daemon_sock,
                        const char *shm_path, const char *afc_addr) {
    AranyaError err;

    c->name = name;
    // TODO: methods for initializing cfg types?
    AranyaAfcConfig afc_cfg = {
        .shm_path = shm_path, .max_channels = MAX_CHANS, .addr = afc_addr};
    AranyaClientConfig cli_cfg = {.daemon_sock = daemon_sock, .afc = afc_cfg};
    err                        = aranya_client_init(&c->client, &cli_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr,
                "error initializing client %s (daemon_sock: %s, shm_path: %s, "
                "afc_addr: %s): %s\r\n",
                c->name, daemon_sock, shm_path, afc_addr,
                aranya_error_to_str(err));
        return err;
    }
    err = aranya_get_device_id(&c->client, &c->id);
    CLIENT_EXPECT("error getting device id", c->name, err);

    err = aranya_get_key_bundle(&c->client, &c->pk);
    CLIENT_EXPECT("error getting key bundle", c->name, err);

    return ARANYA_ERROR_SUCCESS;
}

// Initialize the Aranya `Team` by first initializing the team's clients and
// then creates the team.
AranyaError init_team(Team *t) {
    AranyaError err;

    // initialize team clients.
    for (int i = 0; i < NUM_CLIENTS; i++) {
        err = init_client(&t->clients_arr[i], client_names[i], daemon_socks[i],
                          shm_paths[i], afc_addrs[i]);
        EXPECT("error initializing team", err);
    }

    // have owner create the team.
    // The `aranya_create_team` method is used to create a new graph for the
    // team to operate on.
    err = aranya_create_team(&t->clients.owner.client, &t->id);
    EXPECT("error creating team", err);

    return ARANYA_ERROR_SUCCESS;
}

// Cleanup Aranya `Team`.
AranyaError cleanup_team(Team *t) {
    AranyaError err;
    AranyaError retErr = ARANYA_ERROR_SUCCESS;

    for (int i = 0; i < NUM_CLIENTS; i++) {
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
AranyaError add_sync_peers(Team *t) {
    AranyaError err;
    AranyaDuration interval = ARANYA_DURATION_MILLISECONDS * 100;

    for (int i = 0; i < NUM_CLIENTS; i++) {
        for (int j = 0; j < NUM_CLIENTS; j++) {
            if (i == j) {
                continue; // don't add self as a sync peer.
            }
            printf("adding sync peer %s to %s\r\n", t->clients_arr[j].name,
                   t->clients_arr[i].name);
            err = aranya_add_sync_peer(&t->clients_arr[i].client, &t->id,
                                       sync_addrs[j], interval);
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
    err = aranya_init_logging();
    EXPECT("error initializing logging", err);

    // initialize the Aranya team.
    err = init_team(t);
    EXPECT("error initializing team", err);

    // add sync peers.
    err = add_sync_peers(t);
    EXPECT("error adding sync peers", err);

    // Team members are added to the team by first calling
    // `aranya_add_device_to_team`, passing in the submitter's client, the
    // team ID and the public key of the device to be added. In a real world
    // scenario, the keys would be exchanged outside of Aranya using something
    // like `scp`.

    // add admin to team.
    err = aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                    &t->clients.admin.pk);
    EXPECT("error adding admin to team", err);

    // upgrade role to admin.
    err = aranya_assign_role(&t->clients.owner.client, &t->id,
                             &t->clients.admin.id, ARANYA_ROLE_ADMIN);
    EXPECT("error assigning admin role", err);

    // add operator to team.
    err = aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                    &t->clients.operator.pk);
    EXPECT("error adding operator to team", err);

    // upgrade role to operator.
    err = aranya_assign_role(&t->clients.owner.client, &t->id,
                             &t->clients.operator.id, ARANYA_ROLE_OPERATOR);
    EXPECT("error assigning operator role", err);

    // add membera to team.
    err = aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                    &t->clients.membera.pk);
    EXPECT("error adding membera to team", err);

    // add memberb to team.
    err = aranya_add_device_to_team(&t->clients.owner.client, &t->id,
                                    &t->clients.memberb.pk);
    EXPECT("error adding memberb to team", err);

    sleep(1);

    // Once all team members are added and the appropriate roles have been
    // assigned, the team works together to send data using Aranya Fast
    // Channels.
    // First, a label must be created to associate a channel to its permitted
    // devices using the `aranya_create_label` function.

    // operator creates AFC labels and assigns them to team members.
    AranyaLabel label = 42;
    err = aranya_create_label(&t->clients.operator.client, &t->id, label);
    EXPECT("error creating afc label", err);

    // Then, the label is assigned to the `Member`s on the team, membera and
    // memberb using `aranya_assign_label`.

    err = aranya_assign_label(&t->clients.operator.client, &t->id,
                              &t->clients.membera.id, label);
    EXPECT("error assigning afc label to membera", err);

    err = aranya_assign_label(&t->clients.operator.client, &t->id,
                              &t->clients.memberb.id, label);
    EXPECT("error assigning afc label to memberb", err);

    // Once the label is created and assigned, the devices that will
    // communicate via Aranya Fast Channels must be assigned a network
    // identifier. This is used by Fast Channels to properly translate
    // between network names and devices. Network identifiers are assigned
    // using the `aranya_afc_assign_net_identifiers` function.

    // assign AFC network addresses.
    err = aranya_afc_assign_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.membera.id,
                                           afc_addrs[MEMBERA]);
    EXPECT("error assigning afc net name to membera", err);

    err = aranya_afc_assign_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.memberb.id,
                                           afc_addrs[MEMBERB]);
    EXPECT("error assigning afc net name to memberb", err);
    // assign AQC network addresses.
    err = aranya_aqc_assign_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.membera.id,
                                           afc_addrs[MEMBERA]);
    EXPECT("error assigning aqc net name to membera", err);

    err = aranya_aqc_assign_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.memberb.id,
                                           afc_addrs[MEMBERB]);
    EXPECT("error assigning aqc net name to memberb", err);

    sleep(1);

    // Queries
    AranyaKeyBundle memberb_keybundle;
    err = aranya_query_device_keybundle(&t->clients.operator.client, &t->id,
                                        &t->clients.memberb.id,
                                        &memberb_keybundle);
    EXPECT("error querying memberb key bundle", err);
    printf(
        "%s key bundle enc_key_len %lu, sign_key_len %lu, ident_key_len %lu "
        "\r\n",
        t->clients_arr[MEMBERB].name, memberb_keybundle.enc_key_len,
        memberb_keybundle.sign_key_len, memberb_keybundle.ident_key_len);
    size_t memberb_afc_net_identifier_len = BUF_LEN;
    char *memberb_afc_net_identifier      = malloc(BUF_LEN);
    bool afc_net_identifier_exists        = false;
    err                                   = aranya_query_afc_net_identifier(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id,
        memberb_afc_net_identifier, &memberb_afc_net_identifier_len,
        &afc_net_identifier_exists);
    EXPECT("error querying memberb afc net identifier", err);
    if (!afc_net_identifier_exists) {
        fprintf(stderr, "expected AFC net identifier to be returned\r\n");
        return ARANYA_ERROR_BUG;
    }
    printf("%s afc net identifier: %s \r\n", t->clients_arr[MEMBERB].name,
           memberb_afc_net_identifier);

    err = aranya_afc_remove_net_identifier(&t->clients.operator.client, &t->id,
                                           &t->clients.memberb.id,
                                           afc_addrs[MEMBERB]);
    EXPECT("error removing memberb afc net identifier", err);
    printf("%s removed afc net identifier: %s \r\n",
           t->clients_arr[MEMBERB].name, memberb_afc_net_identifier);
    memberb_afc_net_identifier_len = BUF_LEN;
    err                            = aranya_query_afc_net_identifier(
        &t->clients.operator.client, &t->id, &t->clients.memberb.id,
        memberb_afc_net_identifier, &memberb_afc_net_identifier_len,
        &afc_net_identifier_exists);
    EXPECT("error querying memberb afc net identifier", err);
    if (afc_net_identifier_exists) {
        fprintf(stderr, "did not expect AFC net identifier to be returned\r\n");
        return ARANYA_ERROR_BUG;
    }
    printf("%s afc net identifier: %s \r\n", t->clients_arr[MEMBERB].name,
           memberb_afc_net_identifier);
    free(memberb_afc_net_identifier);

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
                                           afc_addrs[MEMBERB]);
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

    bool exists = false;
    err = aranya_query_label_exists(&t->clients.membera.client, &t->id, &label,
                                    &exists);
    EXPECT("error querying label exists", err);
    printf("%s label exists: %s \r\n", t->clients_arr[MEMBERB].name,
           exists ? "true" : "false");

    // Once membera and memberb have been assigned the label and their network
    // identifiers, a Fast Channel can be created. In this example, membera
    // will create the channel using `aranya_afc_create_bidi_channel`. This will
    // create a bidirectional Aranya Fast Channel.

    // create AFC channel between membera and memberb.
    AranyaChannelId chan_id;
    err = aranya_afc_create_bidi_channel(&t->clients.membera.client, &t->id,
                                         afc_addrs[MEMBERB], label, &chan_id);
    EXPECT("error creating afc channel", err);
    AranyaDuration timeout = ARANYA_DURATION_SECONDS * 1;
    // TODO: poll in separate task.
    // poll for ctrl message.
    while (true) {
        AranyaError err1, err2;

        printf("polling for ctrl\r\n");
        err1 = aranya_afc_poll_data(&t->clients.membera.client, timeout);
        err2 = aranya_afc_poll_data(&t->clients.memberb.client, timeout);
        if (err1 == ARANYA_ERROR_TIMEOUT && err2 == ARANYA_ERROR_TIMEOUT) {
            printf("polling timed out\r\n");
            break;
        }
    }

    // Once created, membera can send a message over the channel using
    // `aranya_afc_send_data`.

    // send AFC data.
    const char *send = "hello world";
    err              = aranya_afc_send_data(&t->clients.membera.client, chan_id,
                                            (const uint8_t *)send, (int)strlen(send));
    EXPECT("error sending data", err);
    printf("%s sent afc message: len: %d \r\n", t->clients_arr[MEMBERA].name,
           (int)strlen(send));

    // poll for data message.
    while (true) {
        AranyaError err1, err2;

        printf("polling for data\r\n");
        err1 = aranya_afc_poll_data(&t->clients.membera.client, timeout);
        err2 = aranya_afc_poll_data(&t->clients.memberb.client, timeout);
        if (err1 == ARANYA_ERROR_TIMEOUT && err2 == ARANYA_ERROR_TIMEOUT) {
            printf("polling timed out\r\n");
            break;
        }
    }

    // Memberb uses `aranya_afc_recv_data` to receive the incoming message.

    // receive AFC data.
    AranyaAfcMsgInfo info;
    uint8_t buf[BUF_LEN];
    size_t len = BUF_LEN;
    bool ok    = false;
    err =
        aranya_afc_recv_data(&t->clients.memberb.client, buf, &len, &info, &ok);
    EXPECT("error receiving data", err);
    if (!ok) {
        fprintf(stderr, "`aranya_afc_recv_data` returned `false`\n");
        return ARANYA_ERROR_AFC;
    }
    printf("%s received afc message from %s: len: %zu, label: %d \r\n",
           t->clients_arr[MEMBERB].name, t->clients_arr[MEMBERA].name, len,
           info.label);
    return ARANYA_ERROR_SUCCESS;
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
