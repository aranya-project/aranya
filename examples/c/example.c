/*
 * Copyright (c) SpiderOak, Inc. All rights reserved.
 */
/**
 * @file example.c
 * @brief Example C application using the Aranya client library.
 */

// Note: this file is formatted with `clang-format`.

#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ENABLE_ARANYA_AFC 1
#define ENABLE_ARANYA_PREVIEW 1
#define ENABLE_ARANYA_EXPERIMENTAL 1
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

// Macro that polls a command until it returns success, otherwise calling
// EXPECT.
#define POLL(C, M)                                                             \
    while (1) {                                                                \
        err = (C);                                                             \
        if (err == ARANYA_ERROR_SUCCESS) {                                     \
            break;                                                             \
        }                                                                      \
        switch (err) {                                                         \
        case ARANYA_ERROR_WOULD_BLOCK:                                         \
            usleep(100000);                                                    \
            continue;                                                          \
        default:                                                               \
            EXPECT((M), err);                                                  \
        }                                                                      \
    }

// Default size for allocated data buffers.
#define BUFFER_LEN 256

// Number of clients on an Aranya team.
#define NUM_CLIENTS 5

// Team members enum. Can index into team member arrays.
typedef enum {
    OWNER,
    ADMIN,
    OPERATOR,
    MEMBERA,
    MEMBERB,
} Members;

// List of Unix domain socket paths for the Aranya clients.
const char* daemon_socks[] = {
    "out/owner/run/uds.sock", "out/admin/run/uds.sock",
    "out/operator/run/uds.sock", "out/membera/run/uds.sock",
    "out/memberb/run/uds.sock"};

// List of names for the Aranya clients.
const char* client_names[] = {"owner", "admin", "operator", "membera",
                              "memberb"};

// List of sync addresses.
const AranyaAddr sync_addrs[] = {"127.0.0.1:10001", "127.0.0.1:10002",
                                 "127.0.0.1:10003", "127.0.0.1:10004",
                                 "127.0.0.1:10005"};

// Aranya client.
typedef struct {
    // Name of Aranya client.
    const char* name;
    // Pointer to Aranya client.
    AranyaClient client;
    // Aranya client's serialized public key bundle.
    uint8_t* pk;
    // Aranya client's serialized public key bundle length.
    size_t pk_len;
    // Aranya client's public id.
    AranyaDeviceId id;
} Client;

// Which PSK seed mode to use for example.
typedef enum {
    GENERATE,
    RAW_IKM,
} PskSeedMode;

// Aranya team.
//
// Contains the team ID and all Aranya clients for the devices on this example's
// team.
typedef struct {
    PskSeedMode seed_mode;
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

// Forward Declarations
AranyaError init_client(Client* c, const char* name, const char* daemon_addr);
AranyaError init_team(Team* t);
AranyaError add_sync_peers(Team* t, AranyaSyncPeerConfig* cfg);
AranyaError run(Team* t);
AranyaError run_afc_example(Team* t);
AranyaError cleanup_team(Team* t);
AranyaError get_role_id_by_name(const struct AranyaRole *role_list,
                                       size_t role_list_len,
                                       const char* name,
                                       struct AranyaRoleId *__output);

typedef struct AranyaChannelIdent {
    AranyaDeviceId* device;
    AranyaChanOp op;
} AranyaChannelIdent;
AranyaError aranya_create_assign_label(AranyaClient* client, AranyaTeamId* id,
                                       const char* label_name,
                                       AranyaLabelId* label_id,
                                       AranyaRoleId managing_role_id,
                                       AranyaChannelIdent* idents,
                                       int num_peers);

AranyaError get_role_id_by_name(const struct AranyaRole *role_list,
                                       size_t role_list_len,
                                       const char*  name,
                                       struct AranyaRoleId *__output) {
    
    AranyaError err;

    for (size_t i = 0; i < role_list_len; i++) {
        AranyaRole role = role_list[i];
        const char* role_name = NULL;
        err = aranya_role_get_name(&role, &role_name);

        if (err != ARANYA_ERROR_SUCCESS) {
            return err;
        }

        if (strcmp(name, role_name) == 0) {
            err = aranya_role_get_id(&role, __output);
            return err;
        }
    }

    return ARANYA_ERROR_OTHER;
}

// Initialize an Aranya `Client` with the given parameters.
AranyaError init_client(Client* c, const char* name, const char* daemon_addr) {
    AranyaError err;
    c->name = name;

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
    c->pk     = calloc(c->pk_len, 1);
    if (c->pk == NULL) {
        abort();
    }
    err = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        // Too small, so the actual size was written to
        // `c->pk_len`.
        uint8_t* new_pk = realloc(c->pk, c->pk_len);
        if (new_pk == NULL) {
            abort();
        }
        c->pk = new_pk;

        err = aranya_get_key_bundle(&c->client, c->pk, &c->pk_len);
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
AranyaError init_team(Team* t) {
    AranyaError err;

    Client* owner = &t->clients.owner;
    Client* admin = &t->clients.admin;
    Client* operator= & t->clients.operator;
    Client* membera = &t->clients.membera;
    Client* memberb = &t->clients.memberb;

    // initialize team clients.
    for (int i = 0; i < NUM_CLIENTS; i++) {
        printf("initializing client: %s\n", client_names[i]);

        Client* client = &t->clients_arr[i];
        err            = init_client(client, client_names[i], daemon_socks[i]);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "unable to initialize client %s: %s\n",
                    client->name, aranya_error_to_str(err));
            return err;
        }
    }

    // Setup team config for owner device.
    AranyaCreateTeamQuicSyncConfigBuilder owner_quic_build;
    err = aranya_create_team_quic_sync_config_builder_init(&owner_quic_build);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr,
                "unable to init `AranyaCreateTeamQuicSyncConfigBuilder`\n");
        return err;
    }

    AranyaSeedIkm ikm;
    if (t->seed_mode == RAW_IKM) {
        err =
            aranya_rand(&t->clients.owner.client, ikm.bytes, sizeof(ikm.bytes));
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "unable to generate random bytes\n");
            return err;
        }
        err = aranya_create_team_quic_sync_config_raw_seed_ikm(
            &owner_quic_build, &ikm);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr,
                    "unable to set `AranyaCreateTeamQuicSyncConfigBuilder` raw "
                    "IKM seed"
                    "mode\n");
            return err;
        }
    } else {
        err = aranya_create_team_quic_sync_config_generate(&owner_quic_build);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(
                stderr,
                "unable to set `AranyaCreateTeamQuicSyncConfigBuilder` generate"
                "mode\n");
            return err;
        }
    }

    AranyaCreateTeamQuicSyncConfig owner_quic_cfg;
    err = aranya_create_team_quic_sync_config_build(&owner_quic_build,
                                                    &owner_quic_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to init `AranyaCreateTeamQuicSyncConfig`\n");
        return err;
    }

    AranyaCreateTeamConfigBuilder owner_build;
    err = aranya_create_team_config_builder_init(&owner_build);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to init `AranyaCreateTeamConfigBuilder`\n");
        return err;
    }

    err = aranya_create_team_config_builder_set_quic_syncer(&owner_build,
                                                            &owner_quic_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr,
                "unable to set `CreateQuicSyncConfig` for "
                "`AranyaTeamConfigBuilder`\n");
        return err;
    }

    // NB: A builder's "_build" method consumes the builder, so
    // do _not_ call "_cleanup" afterward.
    AranyaCreateTeamConfig owner_cfg;
    err = aranya_create_team_config_build(&owner_build, &owner_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to init `AranyaCreateTeamConfig`\n");
        return err;
    }

    // have owner create the team.
    // The `aranya_create_team` method is used to create a new graph for the
    // team to operate on.
    err = aranya_create_team(&t->clients.owner.client, &owner_cfg, &t->id);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to create team\n");
        return err;
    }

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

    // Team members are added to the team by first calling
    // `aranya_add_device_to_team`, passing in the submitter's client, the
    // team ID ,the public key of the device to be added, and the role ID. In a real world
    // scenario, the keys would be exchanged outside of Aranya using
    // something like `scp`.

    size_t default_roles_len = 3;
    AranyaRole default_roles[default_roles_len];

    // setup default roles.
    err = aranya_setup_default_roles(&owner->client, &t->id, default_roles, &default_roles_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr,
                "unable to set up default roles\n");
        return err;
    }

    // Get the ID of the admin role.
    AranyaRoleId admin_role_id;
    err = get_role_id_by_name(default_roles, default_roles_len, "admin", &admin_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to get 'admin' role from list of default roles\n");
        return err;
    }

    // add admin to team.
    err = aranya_add_device_to_team(&owner->client, &t->id, admin->pk,
                                    admin->pk_len, &admin_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to add admin to team\n");
        return err;
    }

    // Get the ID of the operator role.
    AranyaRoleId operator_role_id;
    err = get_role_id_by_name(default_roles, default_roles_len, "operator", &operator_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to get 'operator' role from list of default roles\n");
        return err;
    }

    // add operator to team.
    err = aranya_add_device_to_team(&owner->client,
                                    &t->id, operator->pk, operator->pk_len, &operator_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to add operator to team\n");
        return err;
    }

    // Get the ID of the member role.
    AranyaRoleId member_role_id;
    err = get_role_id_by_name(default_roles, default_roles_len, "member", &member_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to get 'member' role from list of default roles\n");
        return err;
    }

    // add membera to team.
    err = aranya_add_device_to_team(&owner->client, &t->id, membera->pk,
                                    membera->pk_len, &member_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to add membera to team\n");
        return err;
    }

    // add memberb to team.
    err = aranya_add_device_to_team(&owner->client, &t->id, memberb->pk,
                                    memberb->pk_len, &member_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to add memberb to team\n");
        return err;
    }

    size_t member_owning_roles_len = 1;
    AranyaRole *member_owning_roles = calloc(member_owning_roles_len, sizeof(AranyaRole));

    // check that there is a single owner for the 'member' role.
    err = aranya_role_owners(&owner->client, &t->id, &member_role_id, member_owning_roles, &member_owning_roles_len);
    EXPECT("unable to get the owning roles for the 'member' role.", err);
    if (member_owning_roles_len != 1) {
        fprintf(stderr, "there should only be 1 owner for the 'member' role. Actual: %zu\n", member_owning_roles_len);
    }

    // Add a new owning role to the 'member' role.
    err = aranya_add_role_owner(&owner->client, &t->id, &member_role_id, &admin_role_id);
    EXPECT("unable to add a new owning role.", err);

    // check that there are 2 owners for the 'member' role.
    err = aranya_role_owners(&owner->client, &t->id, &member_role_id, member_owning_roles, &member_owning_roles_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("handling buffer too small error\n");
        member_owning_roles = realloc(member_owning_roles, member_owning_roles_len * sizeof(AranyaRole));
        err = aranya_role_owners(&owner->client, &t->id, &member_role_id, member_owning_roles, &member_owning_roles_len);
    }
    EXPECT("unable to get the owning roles for the 'member' role", err);
    if (member_owning_roles_len != 2) {
        fprintf(stderr, "there should only be 2 owners for the 'member' role. Actual:%zu\n", member_owning_roles_len);
    }

     // Remove an owning role from the 'member' role.
    err = aranya_remove_role_owner(&owner->client, &t->id, &member_role_id, &admin_role_id);
    EXPECT("unable to remove an owning role.", err);

    // check that there is now just 1 owner for the 'member' role after removing an owning role.
    err = aranya_role_owners(&owner->client, &t->id, &member_role_id, member_owning_roles, &member_owning_roles_len);
    EXPECT("unable to get the owning roles for the 'member' role.", err);
    if (member_owning_roles_len != 1) {
        fprintf(stderr, "there should only be 1 owner for the 'member' role. Actual: %zu\n", member_owning_roles_len);
    }

    // add_team() for each non-owner device
    for (int i = 1; i < NUM_CLIENTS; i++) {
        printf("add_team() client: %s\n", client_names[i]);

        // Setup team config for non-owner devices.
        // QUIC syncer PSK must be set.
        AranyaAddTeamQuicSyncConfigBuilder quic_build;
        err = aranya_add_team_quic_sync_config_builder_init(&quic_build);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr,
                    "unable to init `AranyaAddTeamQuicSyncConfigBuilder`\n");
            return err;
        }

        AranyaTeamId team_id_from_peer = t->id;
        if (t->seed_mode == RAW_IKM) {
            err = aranya_add_team_quic_sync_config_raw_seed_ikm(&quic_build,
                                                                &ikm);
            if (err != ARANYA_ERROR_SUCCESS) {
                fprintf(stderr,
                        "unable to set `AranyaAddTeamQuicSyncConfigBuilder` "
                        "raw IKM "
                        "seed\n");
                return err;
            }
        } else {
            printf("encrypting PSK seed for peer\n");
            size_t wrapped_seed_len = 100;
            uint8_t* wrapped_seed   = calloc(wrapped_seed_len, 1);
            err                     = aranya_encrypt_psk_seed_for_peer(
                &t->clients.owner.client, &t->id, t->clients_arr[i].pk,
                t->clients_arr[i].pk_len, wrapped_seed, &wrapped_seed_len);
            if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
                printf("handling buffer too small error\n");
                wrapped_seed = realloc(wrapped_seed, wrapped_seed_len);
                err          = aranya_encrypt_psk_seed_for_peer(
                    &t->clients.owner.client, &t->id, t->clients_arr[i].pk,
                    t->clients_arr[i].pk_len, wrapped_seed, &wrapped_seed_len);
            }
            if (err != ARANYA_ERROR_SUCCESS) {
                fprintf(stderr,
                        "unable to encrypt psk seed for peer, seed_len=%zu\n",
                        wrapped_seed_len);
                return err;
            }

            // Note: this is where the team owner will send the encrypted PSK
            // seed to the peer.

            err = aranya_add_team_quic_sync_config_wrapped_seed(
                &quic_build, wrapped_seed, wrapped_seed_len);
            if (err != ARANYA_ERROR_SUCCESS) {
                fprintf(stderr,
                        "unable to set `AranyaAddTeamQuicSyncConfigBuilder` "
                        "wrapped "
                        "seed\n");
                return err;
            }
        }

        AranyaAddTeamQuicSyncConfig quic_cfg;
        err = aranya_add_team_quic_sync_config_build(&quic_build, &quic_cfg);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "unable to init `AranyaAddTeamQuicSyncConfig`\n");
            return err;
        }

        AranyaAddTeamConfigBuilder build;
        err = aranya_add_team_config_builder_init(&build);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "unable to init `AranyaAddTeamConfigBuilder`\n");
            return err;
        }

        err = aranya_add_team_config_builder_set_quic_syncer(&build, &quic_cfg);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr,
                    "unable to set `QuicSyncConfig` for "
                    "`AranyaAddTeamConfigBuilder`\n");
            return err;
        }

        err = aranya_add_team_config_builder_set_id(&build, &team_id_from_peer);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr,
                    "unable to set `Id` for "
                    "`AranyaAddTeamConfigBuilder`\n");
            return err;
        }

        // NB: A builder's "_build" method consumes the builder, so
        // do _not_ call "_cleanup" afterward.
        AranyaAddTeamConfig cfg;
        err = aranya_add_team_config_build(&build, &cfg);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "unable to init `AranyaAddTeamConfig`\n");
            return err;
        }

        Client* client = &t->clients_arr[i];
        err            = aranya_add_team(&client->client, &cfg);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "unable to add_team() for client: %s\n",
                    client_names[i]);
            return err;
        }
    }

    // assign role management permissions.
    err = aranya_assign_role_management_permission(&owner->client, &t->id, &operator_role_id, &admin_role_id, "CanAssignRole");
    EXPECT("unable to assign role management permission", err);
    err = aranya_assign_role_management_permission(&owner->client, &t->id, &operator_role_id, &admin_role_id, "CanRevokeRole");
    EXPECT("unable to assign role management permission", err);

    err = aranya_sync_now(&admin->client, &t->id, sync_addrs[OWNER], NULL);
    EXPECT("error calling `sync_now` to sync with peer: admin->owner", err);

    err = aranya_revoke_role(&admin->client, &t->id, &operator->id, &operator_role_id);
    EXPECT("unable to revoke 'operator' role from 'operator'", err);

    err = aranya_assign_role(&admin->client, &t->id, &operator->id, &operator_role_id);
    EXPECT("unable to assign 'operator' role to 'operator'\n", err);
    
    err = aranya_sync_now(&owner->client, &t->id, sync_addrs[ADMIN], NULL);
    EXPECT("error calling `sync_now` to sync with pee: owner->adminr", err);

    err = aranya_revoke_role_management_permission(&owner->client, &t->id, &operator_role_id, &admin_role_id, "CanRevokeRole");
    EXPECT("unable to revoke role management permission", err);

    return ARANYA_ERROR_SUCCESS;

exit:
    return err;
}

// Cleanup Aranya `Team`.
AranyaError cleanup_team(Team* t) {
    AranyaError err;
    AranyaError retErr = ARANYA_ERROR_SUCCESS;

    for (int i = 0; i < NUM_CLIENTS; i++) {
        printf("removing %s device from team\n", t->clients_arr[i].name);
        err = aranya_remove_team(&t->clients_arr[i].client, &t->id);
        if (err != ARANYA_ERROR_SUCCESS) {
            fprintf(stderr, "error removing device from team %s: %s\n",
                    t->clients_arr[i].name, aranya_error_to_str(err));
            retErr = err;
        }
        printf("freeing %s pk\n", t->clients_arr[i].name);
        free(t->clients_arr[i].pk);
        printf("cleaning up %s client\n", t->clients_arr[i].name);
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
AranyaError add_sync_peers(Team* t, AranyaSyncPeerConfig* cfg) {
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

// Run the example.
AranyaError run(Team* t) {
    AranyaError err;
    AranyaDeviceId* devices = NULL;

    Client* operator= & t->clients.operator;
    Client* memberb = &t->clients.memberb;

    // initialize logging.
    printf("initializing logging\n");
    err = aranya_init_logging();
    EXPECT("error initializing logging", err);

    // initialize the Aranya team.
    printf("initializing team\n");
    err = init_team(t);
    EXPECT("unable to initialize team", err);

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

    sleep(1);

    // Queries
    printf("running factdb queries\n");

    size_t devices_len = 256;
    devices            = calloc(devices_len, sizeof(AranyaDeviceId));
    if (devices == NULL) {
        abort();
    }
    err = aranya_team_devices(&operator->client, &t->id, devices,
                                       &devices_len);
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

    uint8_t memberb_keybundle[1024] = {0};
    size_t memberb_keybundle_len    = sizeof(memberb_keybundle);
    err = aranya_team_device_keybundle(&operator->client, &t->id, &memberb->id,
                                        memberb_keybundle,
                                        &memberb_keybundle_len);
    EXPECT("error querying memberb key bundle", err);
    printf(
        "%s key bundle len: %zu"
        "\n",
        t->clients_arr[MEMBERB].name, memberb_keybundle_len);

    err = run_afc_example(t);
    EXPECT("error running afc example", err);

exit:
    free(devices);
    return err;
}

AranyaError aranya_create_assign_label(AranyaClient* client, AranyaTeamId* id,
                                       const char* label_name,
                                       AranyaLabelId* label_id,
                                       AranyaRoleId managing_role_id,
                                       AranyaChannelIdent* idents,
                                       int num_peers) {
    AranyaError err;

    err = aranya_create_label(client, id, label_name, &managing_role_id, label_id);
    EXPECT("error creating label", err);

    for (int i = 0; i < num_peers; i++) {
        AranyaChannelIdent ident = idents[i];
        err = aranya_assign_label(client, id, ident.device, label_id, ident.op);
        EXPECT("error assigning label", err);
    }

exit:
    return err;
}

// Run the AFC example.
AranyaError run_afc_example(Team* t) {
    Client* owner= & t->clients.owner;
    Client* membera = &t->clients.membera;
    Client* memberb = &t->clients.memberb;

    unsigned char* ciphertext = NULL;
    unsigned char* plaintext  = NULL;
    AranyaRole* roles = NULL;

    AranyaError err;

    // Create a new label and assign it to Member A/Member B. Note that Member A
    // can only send (seal) data, and Member B can only receive (open) data.
    AranyaLabelId label_id;
    AranyaChannelIdent idents[] = {{&membera->id, ARANYA_CHAN_OP_SEND_ONLY},
                                   {&memberb->id, ARANYA_CHAN_OP_RECV_ONLY}};

    size_t roles_len = 0;
    roles = calloc(roles_len, sizeof(AranyaRole));

    err = aranya_team_roles(&owner->client, &t->id, roles, &roles_len);
    if (err == ARANYA_ERROR_BUFFER_TOO_SMALL) {
        printf("handling buffer too small error. roles_len: %zu\n", roles_len);
        roles = realloc(roles, roles_len * sizeof(AranyaRole));
        if (roles == NULL) {
            abort();
        }

        printf("handled buffer reallocation. roles_len: %zu\n", roles_len);
        err = aranya_team_roles(&owner->client, &t->id, roles, &roles_len);
        printf("Re tried fefching list of roles\n");
    }
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to get list of roles\n");
        return err;
    }

    AranyaRoleId owner_role_id;
    err = get_role_id_by_name(roles, roles_len, "owner", &owner_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to get 'owner' role from list of roles\n");
        return err;
    }


    err = aranya_create_assign_label(&owner->client, &t->id, "uni_label",
                                     &label_id, owner_role_id, idents, 2);
    if (err != ARANYA_ERROR_SUCCESS) {
        goto exit;
    }

    // Tell them both to sync with the owner to see their new label.
    err = aranya_sync_now(&membera->client, &t->id, sync_addrs[OWNER], NULL);
    EXPECT("error calling `sync_now` to sync with peer", err);

    err = aranya_sync_now(&memberb->client, &t->id, sync_addrs[OWNER], NULL);
    EXPECT("error calling `sync_now` to sync with peer", err);

    // Create a new uni send channel, which will give back an `AranyaAfcChannel`
    // and a control message to send to the other peer (in this case, it's local
    // so there's no "transport" layer sending the ctrl_msg to Member B).
    printf("membera: Creating an afc send channel\n");
    AranyaAfcSendChannel afc_send_channel;
    AranyaAfcCtrlMsg recv_message;
    err = aranya_afc_create_uni_send_channel(&membera->client, &t->id,
                                             &memberb->id, &label_id,
                                             &afc_send_channel, &recv_message);
    EXPECT("error creating a uni send channel for membera", err);

    AranyaAfcChannelId send_id;
    printf("membera: Getting afc send channel id\n");
    err = aranya_afc_send_channel_get_id(&afc_send_channel, &send_id);
    EXPECT("error getting afc send channel id", err);
    char send_id_str[ARANYA_ID_STR_LEN] = {0};
    size_t send_id_str_len              = sizeof(send_id_str);
    err = aranya_id_to_str(&send_id.id, send_id_str, &send_id_str_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to convert ID to string\n");
        return err;
    }
    printf("membera: afc send channel id: %s \n", send_id_str);

    // In production, you would get the underlying buffer from the control
    // message, and send it to the other peer via your transport of choice,
    // which will allow them to create the other side of the channel.
    const uint8_t* bytes_ptr;
    size_t bytes_len;
    err = aranya_afc_ctrl_msg_get_bytes(&recv_message, &bytes_ptr, &bytes_len);
    EXPECT("error getting ptr+len from `AranyaAfcCtrlMsg`", err);

    // Note that since we created a uni send channel on Member A's side above,
    // Member B here will get a uni receive channel.
    printf("memberb: Receiving ctrl message for afc recv channel\n");
    AranyaAfcReceiveChannel afc_recv_channel;
    err = aranya_afc_recv_ctrl(&memberb->client, &t->id, bytes_ptr, bytes_len,
                               &afc_recv_channel);
    EXPECT("error creating a channel from control message", err);

    printf("membera: Getting afc receive channel id\n");
    AranyaAfcChannelId recv_id;
    err = aranya_afc_receive_channel_get_id(&afc_recv_channel, &recv_id);
    EXPECT("error getting afc recv channel id", err);
    char recv_id_str[ARANYA_ID_STR_LEN] = {0};
    size_t recv_id_str_len              = sizeof(recv_id_str);
    err = aranya_id_to_str(&recv_id.id, recv_id_str, &recv_id_str_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "unable to convert ID to string\n");
        return err;
    }
    printf("membera: afc recv channel id: %s \n", recv_id_str);

    // Now we need to define some data we want to send, in this case a
    // simple string. We need both the original data, as well as a buffer to
    // store the resulting ciphertext, which includes some additional
    // overhead.
    const char* afc_msg   = "one way msg";
    size_t afc_msg_len    = strlen(afc_msg);
    size_t ciphertext_len = afc_msg_len + ARANYA_AFC_CHANNEL_OVERHEAD;
    ciphertext            = calloc(ciphertext_len, 1);
    if (ciphertext == NULL) {
        abort();
    }

    // Use the channel to encrypt and authenticate our data, and store the
    // encrypted result in our ciphertext buffer.
    printf("membera: Sealing afc data for memberb\n");
    err = aranya_afc_channel_seal(&afc_send_channel, (const uint8_t*)afc_msg,
                                  afc_msg_len, ciphertext, &ciphertext_len);
    EXPECT("error sealing afc message", err);

    // Here, you would send the ciphertext to the other peer using the transport
    // of your choice. Aranya Fast Channels (AFC) does not provide a transport,
    // only the encryption capabilities to make such an operation safe.

    // The peer needs to allocate a buffer to decrypt the data back into, minus
    // channel overhead. This allows it to calculate the original data's length.
    size_t plaintext_len = ciphertext_len - ARANYA_AFC_CHANNEL_OVERHEAD;
    plaintext            = calloc(plaintext_len, 1);
    if (plaintext == NULL) {
        abort();
    }

    // Here, we open the message and get back the original data, as well as a
    // sequence number, which allows you to reorder messages that may have been
    // received out-of-order using `aranya_afc_seq_cmp()` to compare two seq.
    printf("memberb: Opening afc data from membera\n");
    AranyaAfcSeq seq;
    err = aranya_afc_channel_open(&afc_recv_channel, ciphertext, ciphertext_len,
                                  plaintext, &plaintext_len, &seq);
    EXPECT("error opening afc message", err);

    // Make sure that the received message matches the originally sent data.
    if (memcmp(afc_msg, plaintext, afc_msg_len)) {
        EXPECT("plaintext does not match input text", ARANYA_ERROR_BUG);
    }

    printf("deleting afc channels\n");
    err = aranya_afc_send_channel_delete(&membera->client, &afc_send_channel);
    EXPECT("error deleting membera's channel", err);

    err =
        aranya_afc_receive_channel_delete(&memberb->client, &afc_recv_channel);
    EXPECT("error deleting memberb's channel", err);

    err = aranya_afc_ctrl_msg_cleanup(&recv_message);
    EXPECT("error cleaning up control message", err);

    // Get the ID of the member role.
    AranyaRoleId member_role_id;
    err = get_role_id_by_name(roles, roles_len, "member", &member_role_id);
    EXPECT("unable to get 'member' role from list of default roles.", err);

    err = aranya_change_role(&owner->client, &t->id, &membera->id, &member_role_id, &owner_role_id);
    EXPECT("unable to change role from 'member' to 'owner'.", err);
exit:
    free(ciphertext);
    free(plaintext);
    return err;
}

// Thread-unique data.
typedef struct {
    AranyaClient* client;
    AranyaTeamId id;
    AranyaLabelId label1;
    AranyaLabelId label2;
    AranyaError result;
} channel_context_t;

int main(int argc, char* argv[]) {
    Team team       = {0};
    AranyaError err = ARANYA_ERROR_OTHER;

    // parse arguments.
    team.seed_mode = GENERATE;
    if (argc >= 2) {
        char* seed_mode_arg = argv[1];
        if (!strncmp(seed_mode_arg, "raw_seed_ikm", 10)) {
            team.seed_mode = RAW_IKM;
        }
    }
    switch (team.seed_mode) {
    case GENERATE:
        printf("PSK generate seed mode\n");
        break;
    case RAW_IKM:
        printf("Raw PSK IKM seed mode\n");
        break;
    }

    // TODO: take work_dirs, shm_paths, daemon_socks, IP addresses as input?

    // run the example.
    err = run(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "application failed: %s\n", aranya_error_to_str(err));
        return EXIT_FAILURE;
    }

    // cleanup team.
    printf("cleaning up the Aranya team \n");
    err = cleanup_team(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
