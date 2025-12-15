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

/* Globals for per-daemon client connection and sync addresses.
    Use static defaults so tests run reproducibly without runtime snprintfs. */
static const char g_owner_uds[128] = "/tmp/afc-run-owner/uds.sock";
static const char g_member1_uds[128] = "/tmp/afc-run-member1/uds.sock";
static const char g_member2_uds[128] = "/tmp/afc-run-member2/uds.sock";
static const char g_owner_sync_addr[64] = "127.0.0.1:42001";
static const char g_member1_sync_addr[64] = "127.0.0.1:42002";
static const char g_member2_sync_addr[64] = "127.0.0.1:42003";

/* Initialize a client */
static AranyaError init_client(Client *c, const char *name, const char *daemon_addr) {
    AranyaError err;
    
    if (name) {
        snprintf(c->name, sizeof(c->name), "%s", name);
    } else {
        c->name[0] = '\0';
    }
    c->name[sizeof(c->name) - 1] = '\0';
    
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
    
    err = aranya_get_device_id(&c->client, &c->id);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_client_cleanup(&c->client);
        return err;
    }
    
    c->pk_len = 1;
    c->pk = calloc(1, 1);
    if (c->pk == NULL) {
        aranya_client_cleanup(&c->client);
        return ARANYA_ERROR_OTHER;
    }
    
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

/* Initialize a team with owner, connecting to specified owner's daemon UDS */
static AranyaError init_team(Team *t, const char *owner_uds) {
    Client *owner = &t->owner;
    memset(owner, 0, sizeof(Client));
    
    AranyaError err = init_client(owner, "Owner", owner_uds);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    AranyaCreateTeamQuicSyncConfigBuilder owner_quic_build;
    err = aranya_create_team_quic_sync_config_builder_init(&owner_quic_build);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Use a raw seed so non-owner peers can join using same PSK */
    memset(&t->team_ikm, 0, sizeof(t->team_ikm));
    err = aranya_rand(&owner->client, t->team_ikm.bytes, sizeof(t->team_ikm.bytes));
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    err = aranya_create_team_quic_sync_config_raw_seed_ikm(&owner_quic_build, &t->team_ikm);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    AranyaCreateTeamQuicSyncConfig owner_quic_cfg;
    err = aranya_create_team_quic_sync_config_build(&owner_quic_build, &owner_quic_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
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
    
    err = aranya_create_team(&owner->client, &owner_cfg, &t->id);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Get the owner role ID */
    size_t team_roles_len = 10;
    AranyaRole team_roles[10];
    err = aranya_team_roles(&owner->client, &t->id, team_roles, &team_roles_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    if (team_roles_len > 0) {
        err = aranya_role_get_id(&team_roles[0], &t->owner_role_id);
        if (err != ARANYA_ERROR_SUCCESS) {
            for (size_t i = 0; i < team_roles_len; i++) {
                aranya_role_cleanup(&team_roles[i]);
            }
            return err;
        }
    }
    
    /* Cleanup role structures */
    for (size_t i = 0; i < team_roles_len; i++) {
        aranya_role_cleanup(&team_roles[i]);
    }
    
    /* Setup default roles to get member role ID */
    size_t default_roles_len = 10;
    AranyaRole default_roles[10];
    err = aranya_setup_default_roles(&owner->client, &t->id, &t->owner_role_id, 
                                     default_roles, &default_roles_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Find and store the member role ID */
    int found_member = 0;
    for (size_t i = 0; i < default_roles_len; i++) {
        const char *role_name = NULL;
        err = aranya_role_get_name(&default_roles[i], &role_name);
        if (err == ARANYA_ERROR_SUCCESS && role_name != NULL) {
            if (strcmp(role_name, "member") == 0) {
                err = aranya_role_get_id(&default_roles[i], &t->member_role_id);
                if (err == ARANYA_ERROR_SUCCESS) {
                    found_member = 1;
                }
                break;
            }
        }
    }
    
    /* Cleanup default roles */
    for (size_t i = 0; i < default_roles_len; i++) {
        aranya_role_cleanup(&default_roles[i]);
    }
    
    if (!found_member) {
        return ARANYA_ERROR_OTHER;
    }
    
    return ARANYA_ERROR_SUCCESS;
}

/* Helper: owner adds member to team and member joins with raw IKM */
static AranyaError add_member_to_team(Team *t, Client *member, const char *member_sync_addr) {
    AranyaError err;
    
    /* Owner adds member device with Member role (required for label assignments) */
    err = aranya_add_device_to_team(&t->owner.client, &t->id, member->pk, member->pk_len, &t->member_role_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Member joins the team using the shared raw IKM */
    AranyaAddTeamQuicSyncConfigBuilder member_quic_build;
    err = aranya_add_team_quic_sync_config_builder_init(&member_quic_build);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    err = aranya_add_team_quic_sync_config_raw_seed_ikm(&member_quic_build, &t->team_ikm);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_add_team_quic_sync_config_builder_cleanup(&member_quic_build);
        return err;
    }
    AranyaAddTeamQuicSyncConfig member_quic_cfg;
    err = aranya_add_team_quic_sync_config_build(&member_quic_build, &member_quic_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    AranyaAddTeamConfigBuilder add_build;
    err = aranya_add_team_config_builder_init(&add_build);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    err = aranya_add_team_config_builder_set_id(&add_build, &t->id);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_add_team_config_builder_cleanup(&add_build);
        return err;
    }
    err = aranya_add_team_config_builder_set_quic_syncer(&add_build, &member_quic_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_add_team_config_builder_cleanup(&add_build);
        return err;
    }
    AranyaAddTeamConfig add_cfg;
    err = aranya_add_team_config_build(&add_build, &add_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    err = aranya_add_team(&member->client, &add_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Setup sync peers for automatic synchronization instead of blocking sync_now */
    if (g_owner_sync_addr[0] && member_sync_addr && member_sync_addr[0]) {
        printf("    Setting up sync peers...\n");
        
        /* Build sync peer config */
        AranyaSyncPeerConfigBuilder sync_builder;
        err = aranya_sync_peer_config_builder_init(&sync_builder);
        if (err == ARANYA_ERROR_SUCCESS) {
            AranyaDuration interval = ARANYA_DURATION_MILLISECONDS * 100;
            aranya_sync_peer_config_builder_set_interval(&sync_builder, interval);
            aranya_sync_peer_config_builder_set_sync_now(&sync_builder);
            
            AranyaSyncPeerConfig sync_config;
            err = aranya_sync_peer_config_build(&sync_builder, &sync_config);
            if (err == ARANYA_ERROR_SUCCESS) {
                /* Add owner as sync peer for member */
                aranya_add_sync_peer(&member->client, &t->id, g_owner_sync_addr, &sync_config);
                
                /* Add member as sync peer for owner */
                aranya_add_sync_peer(&t->owner.client, &t->id, member_sync_addr, &sync_config);
                
                printf("    Sync peers configured, waiting for initial sync...\n");
                sleep_ms(500);  /* Reduced - sync peers handle automatic sync */
            }
            aranya_sync_peer_config_builder_cleanup(&sync_builder);
        }
    }
    
    return ARANYA_ERROR_SUCCESS;
}

/* Helper to setup a team with two members */
static AranyaError setup_team_with_members(Team *team) {
    printf("    [DEBUG] setup_team_with_members: Starting init_team\n");
    fflush(stdout);
    AranyaError err = init_team(team, g_owner_uds[0] ? g_owner_uds : "run/uds.sock");
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("    [DEBUG] setup_team_with_members: init_team failed: %s\n", aranya_error_to_str(err));
        fflush(stdout);
        return err;
    }
    printf("    [DEBUG] setup_team_with_members: init_team succeeded\n");
    fflush(stdout);
    
    printf("    [DEBUG] setup_team_with_members: Initializing member1 client\n");
    fflush(stdout);
    err = init_client(&team->member1, "Member1", g_member1_uds[0] ? g_member1_uds : "run/uds.sock");
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("    [DEBUG] setup_team_with_members: member1 init_client failed: %s\n", aranya_error_to_str(err));
        fflush(stdout);
        return err;
    }
    printf("    [DEBUG] setup_team_with_members: member1 initialized\n");
    fflush(stdout);
    
    printf("    [DEBUG] setup_team_with_members: Initializing member2 client\n");
    fflush(stdout);
    err = init_client(&team->member2, "Member2", g_member2_uds[0] ? g_member2_uds : "run/uds.sock");
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("    [DEBUG] setup_team_with_members: member2 init_client failed: %s\n", aranya_error_to_str(err));
        fflush(stdout);
        return err;
    }
    printf("    [DEBUG] setup_team_with_members: member2 initialized\n");
    fflush(stdout);
    
    printf("    [DEBUG] setup_team_with_members: Adding member1 to team\n");
    fflush(stdout);
    err = add_member_to_team(team, &team->member1, g_member1_sync_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("    [DEBUG] setup_team_with_members: add_member_to_team(member1) failed: %s\n", aranya_error_to_str(err));
        fflush(stdout);
        return err;
    }
    printf("    [DEBUG] setup_team_with_members: member1 added to team\n");
    fflush(stdout);
    
    printf("    [DEBUG] setup_team_with_members: Adding member2 to team\n");
    fflush(stdout);
    err = add_member_to_team(team, &team->member2, g_member2_sync_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("    [DEBUG] setup_team_with_members: add_member_to_team(member2) failed: %s\n", aranya_error_to_str(err));
        fflush(stdout);
        return err;
    }
    printf("    [DEBUG] setup_team_with_members: member2 added to team\n");
    fflush(stdout);
    
    printf("    [DEBUG] setup_team_with_members: Complete!\n");
    fflush(stdout);
    return ARANYA_ERROR_SUCCESS;
}

/* Helper to cleanup team */
static void cleanup_team(Team *team) {
    if (team->member2.pk) free(team->member2.pk);
    aranya_client_cleanup(&team->member2.client);
    if (team->member1.pk) free(team->member1.pk);
    aranya_client_cleanup(&team->member1.client);
    if (team->owner.pk) free(team->owner.pk);
    aranya_client_cleanup(&team->owner.client);
}

/* Test: afc_create_channel (creates send channel) */
static int test_afc_create_channel(void) {
    printf("\n=== TEST: afc_create_channel ===\n");
    fflush(stdout);
    
    printf("  [DEBUG] test_afc_create_channel: Starting\n");
    fflush(stdout);
    Team team = {0};
    printf("  [DEBUG] test_afc_create_channel: Calling setup_team_with_members\n");
    fflush(stdout);
    AranyaError err = setup_team_with_members(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to setup team: %s\n", aranya_error_to_str(err));
        fflush(stdout);
        cleanup_team(&team);
        return 0;
    }
    printf("  [DEBUG] test_afc_create_channel: Team setup succeeded\n");
    fflush(stdout);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to setup team: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    AranyaLabelId label_id;
    err = aranya_create_label(&team.owner.client, &team.id, "SEND_LABEL", &team.owner_role_id, &label_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create label: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member1.id, 
                             &label_id, ARANYA_CHAN_OP_SEND_ONLY);
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member2.id, 
                             &label_id, ARANYA_CHAN_OP_RECV_ONLY);
    
    /* Wait for automatic sync (sync peers are configured with sync_now flag) */
    printf("  Waiting for label assignments to sync...\n");
    sleep_ms(3000);
    
    /* Create send channel from member1 to member2 (new API) */
    AranyaAfcSendChannel send_channel;
    AranyaAfcCtrlMsg ctrl_msg;
    
    printf("  Creating AFC send channel from member1 to member2...\n");
    err = aranya_afc_create_channel(&team.member1.client, &team.id, &team.member2.id, 
                                    &label_id, &send_channel, &ctrl_msg);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create AFC channel: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    printf("  ✓ AFC send channel created\n");
    
    /* Cleanup */
    err = aranya_afc_send_channel_delete(&team.member1.client, &send_channel);
    aranya_afc_ctrl_msg_cleanup(&ctrl_msg);
    cleanup_team(&team);
    
    return 1;
}

/* Test: afc_accept_channel (creates receive channel from control message) */
static int test_afc_accept_channel(void) {
    printf("\n=== TEST: afc_accept_channel ===\n");
    
    Team team = {0};
    AranyaError err = setup_team_with_members(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to setup team: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    AranyaLabelId label_id;
    err = aranya_create_label(&team.owner.client, &team.id, "CHANNEL_LABEL", &team.owner_role_id, &label_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create label: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    printf("  ✓ Label created\n");
    
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member1.id, 
                             &label_id, ARANYA_CHAN_OP_SEND_ONLY);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to assign label to member1 (SEND_ONLY): %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    printf("  ✓ Label assigned to member1 (SEND_ONLY)\n");
    
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member2.id, 
                             &label_id, ARANYA_CHAN_OP_RECV_ONLY);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to assign label to member2 (RECV_ONLY): %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    printf("  ✓ Label assigned to member2 (RECV_ONLY)\n");
    
    /* Wait for sync peers to propagate the label assignments */
    printf("DEBUG: Waiting for sync to propagate label assignments...\n");
    sleep_ms(1000);  /* Reduced from 8000ms */
    
    /* Member1 creates send channel */
    AranyaAfcSendChannel send_channel;
    AranyaAfcCtrlMsg ctrl_msg;
    
    err = aranya_afc_create_channel(&team.member1.client, &team.id, &team.member2.id, 
                                    &label_id, &send_channel, &ctrl_msg);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create send channel: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    /* Get control message bytes */
    const uint8_t *ctrl_bytes;
    size_t ctrl_len;
    aranya_afc_ctrl_msg_get_bytes(&ctrl_msg, &ctrl_bytes, &ctrl_len);
    printf("  ✓ Send channel created with control message (%zu bytes)\n", ctrl_len);
    
    /* Member2 accepts the channel using the control message */
    AranyaAfcReceiveChannel recv_channel;
    err = aranya_afc_accept_channel(&team.member2.client, &team.id, ctrl_bytes, ctrl_len, &recv_channel);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to accept channel: %s\n", aranya_error_to_str(err));
        aranya_afc_send_channel_delete(&team.member1.client, &send_channel);
        aranya_afc_ctrl_msg_cleanup(&ctrl_msg);
        cleanup_team(&team);
        return 0;
    }
    
    printf("  ✓ Receive channel created by accepting control message\n");
    
    /* Cleanup */
    err = aranya_afc_receive_channel_delete(&team.member2.client, &recv_channel);
    err = aranya_afc_send_channel_delete(&team.member1.client, &send_channel);
    aranya_afc_ctrl_msg_cleanup(&ctrl_msg);
    cleanup_team(&team);
    
    return 1;
}

/* Test: afc_channel_seal and afc_channel_open */
static int test_afc_seal_open(void) {
    printf("\n=== TEST: afc_channel_seal and afc_channel_open ===\n");
    
    Team team = {0};
    AranyaError err = setup_team_with_members(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to setup team: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    AranyaLabelId label_id;
    err = aranya_create_label(&team.owner.client, &team.id, "SEAL_OPEN_LABEL", &team.owner_role_id, &label_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create label: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    printf("  ✓ Label created\n");
    
    /* Assign SEND_ONLY to member1 and RECV_ONLY to member2 */
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member1.id, 
                             &label_id, ARANYA_CHAN_OP_SEND_ONLY);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to assign SEND_ONLY label to member1: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    printf("  ✓ Label assigned to member1 (SEND_ONLY)\n");
    
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member2.id, 
                             &label_id, ARANYA_CHAN_OP_RECV_ONLY);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to assign RECV_ONLY label to member2: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    printf("  ✓ Label assigned to member2 (RECV_ONLY)\n");
    
    /* Wait for sync peers to propagate the label assignments */
    printf("  Waiting for sync to propagate label assignments...\n");
    sleep_ms(1000);  /* Reduced from 8000ms */
    
    /* Create send channel on member1 */
    AranyaAfcSendChannel sender_channel;
    AranyaAfcCtrlMsg sender_ctrl;
    
    err = aranya_afc_create_channel(&team.member1.client, &team.id, &team.member2.id, 
                                    &label_id, &sender_channel, &sender_ctrl);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create send channel: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    printf("  ✓ Send channel created\n");
    
    /* Get control message bytes to send to member2 */
    const uint8_t *ctrl_bytes;
    size_t ctrl_len;
    aranya_afc_ctrl_msg_get_bytes(&sender_ctrl, &ctrl_bytes, &ctrl_len);
    printf("  ✓ Control message: %zu bytes\n", ctrl_len);
    
    /* Create receiver channel on member2 using control message */
    AranyaAfcReceiveChannel receiver_channel;
    
    err = aranya_afc_accept_channel(&team.member2.client, &team.id, ctrl_bytes, ctrl_len, 
                                    &receiver_channel);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create receiver from ctrl: %s\n", aranya_error_to_str(err));
        aranya_afc_send_channel_delete(&team.member1.client, &sender_channel);
        aranya_afc_ctrl_msg_cleanup(&sender_ctrl);
        cleanup_team(&team);
        return 0;
    }
    
    printf("  ✓ Receiver channel created from control message\n");
    
    /* Seal a message */
    const char *plaintext = "Hello, secure AFC!";
    size_t plaintext_len = strlen(plaintext);
    size_t ciphertext_len = plaintext_len + ARANYA_AFC_CHANNEL_OVERHEAD;
    uint8_t *ciphertext = calloc(ciphertext_len, 1);
    
    err = aranya_afc_channel_seal(&sender_channel, (const uint8_t *)plaintext, 
                                  plaintext_len, ciphertext, &ciphertext_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to seal message: %s\n", aranya_error_to_str(err));
        free(ciphertext);
        aranya_afc_receive_channel_delete(&team.member2.client, &receiver_channel);
        aranya_afc_send_channel_delete(&team.member1.client, &sender_channel);
        aranya_afc_ctrl_msg_cleanup(&sender_ctrl);
        cleanup_team(&team);
        return 0;
    }
    
    printf("  ✓ Message sealed: %zu bytes -> %zu bytes\n", plaintext_len, ciphertext_len);
    
    /* Open the message */
    size_t decrypted_len = ciphertext_len - ARANYA_AFC_CHANNEL_OVERHEAD;
    uint8_t *decrypted = calloc(decrypted_len + 1, 1);
    AranyaAfcSeq seq;
    
    err = aranya_afc_channel_open(&receiver_channel, ciphertext, ciphertext_len, 
                                  decrypted, &decrypted_len, &seq);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to open message: %s\n", aranya_error_to_str(err));
        free(decrypted);
        free(ciphertext);
        aranya_afc_receive_channel_delete(&team.member2.client, &receiver_channel);
        aranya_afc_send_channel_delete(&team.member1.client, &sender_channel);
        aranya_afc_ctrl_msg_cleanup(&sender_ctrl);
        cleanup_team(&team);
        return 0;
    }
    
    decrypted[decrypted_len] = '\0';
    printf("  ✓ Message opened: \"%s\"\n", decrypted);
    
    /* Verify decrypted matches original */
    int match = (strcmp((char *)decrypted, plaintext) == 0);
    if (!match) {
        printf("  ✗ Decrypted message does not match original\n");
        printf("    Expected: \"%s\"\n", plaintext);
        printf("    Got: \"%s\"\n", (char *)decrypted);
        aranya_afc_seq_cleanup(&seq);
        free(decrypted);
        free(ciphertext);
        aranya_afc_receive_channel_delete(&team.member2.client, &receiver_channel);
        aranya_afc_send_channel_delete(&team.member1.client, &sender_channel);
        aranya_afc_ctrl_msg_cleanup(&sender_ctrl);
        cleanup_team(&team);
        return 0;
    }
    printf("  ✓ Decrypted message matches original\n");
    
    /* Test sequence number retrieved from channel_open */
    printf("  ✓ Sequence number retrieved from channel_open\n");
    
    /* Cleanup */
    aranya_afc_seq_cleanup(&seq);
    free(decrypted);
    free(ciphertext);
    aranya_afc_receive_channel_delete(&team.member2.client, &receiver_channel);
    aranya_afc_send_channel_delete(&team.member1.client, &sender_channel);
    aranya_afc_ctrl_msg_cleanup(&sender_ctrl);
    cleanup_team(&team);
    
    return 1;
}

int main(int argc, const char *argv[]) {
#if defined(ENABLE_ARANYA_PREVIEW)
    setenv("ARANYA_CAPI", "aranya=debug", 1);
    
    AranyaError err = aranya_init_logging();
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "Failed to initialize logging: %s\n", aranya_error_to_str(err));
        return EXIT_FAILURE;
    }
    
    printf("Running aranya-client-capi AFC tests\n");
    printf("====================================\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <daemon-path>\n", argc > 0 ? argv[0] : "TestAfc");
        return EXIT_FAILURE;
    }
    const char *daemon_path = argv[1];
    
    /* Clean up any stray daemon processes from previous runs */
    printf("Cleaning up any stray daemon processes...\n");
    system("pkill -TERM -f 'aranya-daemon.*afc-run' 2>/dev/null || true");
    sleep_ms(500);
    system("pkill -KILL -f 'aranya-daemon.*afc-run' 2>/dev/null || true");
    
    /* Using static defaults for UDS and sync addresses; spawn daemons */
    printf("Spawning owner daemon: %s\n", daemon_path);
    pid_t owner_pid = spawn_daemon_at(daemon_path, "/tmp/afc-run-owner", "test-daemon-owner", "/afc-owner", 42001);
    printf("Owner Daemon PID: %d\n", owner_pid);
    
    printf("Spawning member1 daemon: %s\n", daemon_path);
    pid_t member1_pid = spawn_daemon_at(daemon_path, "/tmp/afc-run-member1", "test-daemon-member1", "/afc-member1", 42002);
    printf("Member1 Daemon PID: %d\n", member1_pid);

    printf("Spawning member2 daemon: %s\n", daemon_path);
    pid_t member2_pid = spawn_daemon_at(daemon_path, "/tmp/afc-run-member2", "test-daemon-member2", "/afc-member2", 42003);
    printf("Member2 Daemon PID: %d\n", member2_pid);

    printf("Waiting 2 seconds for daemons to initialize...\n");
    sleep_ms(2000);  /* Reduced from 7000ms */
    printf("Daemons should be ready now\n");

    /* Test AFC channel operations */    
    if (!test_afc_create_channel()) {
        printf("FAILED: test_afc_create_channel\n");
        kill(owner_pid, SIGTERM);
        kill(member1_pid, SIGTERM);
        kill(member2_pid, SIGTERM);
        return EXIT_FAILURE;
    }
    
    if (!test_afc_accept_channel()) {
        printf("FAILED: test_afc_accept_channel\n");
        kill(owner_pid, SIGTERM);
        kill(member1_pid, SIGTERM);
        kill(member2_pid, SIGTERM);
        return EXIT_FAILURE;
    }
    
    if (!test_afc_seal_open()) {
        printf("FAILED: test_afc_seal_open\n");
        kill(owner_pid, SIGTERM);
        kill(member1_pid, SIGTERM);
        kill(member2_pid, SIGTERM);
        return EXIT_FAILURE;
    }

    printf("\n====================================\n");
    printf("ALL AFC TESTS PASSED\n");
    
    /* Clean up daemons */
    printf("Cleaning up daemons...\n");
    kill(owner_pid, SIGTERM);
    kill(member1_pid, SIGTERM);
    kill(member2_pid, SIGTERM);
    
    /* Wait for daemons to exit */
    waitpid(owner_pid, NULL, 0);
    waitpid(member1_pid, NULL, 0);
    waitpid(member2_pid, NULL, 0);
    printf("Daemons terminated\n");
    
    return EXIT_SUCCESS;
#else
    printf("ENABLE_ARANYA_PREVIEW not defined; skipping AFC tests\n");
    return EXIT_SUCCESS;
#endif
}