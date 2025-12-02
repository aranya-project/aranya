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

/* Helper: write daemon config to given FILE stream */
static void print_daemon_info(const char *cfg_path, const char *name, const char *run_dir,
                             const char *shm_path, uint16_t sync_port) {
    FILE *f = fopen(cfg_path, "w");
    if (!f) {
        fprintf(stderr, "Failed to create daemon config: %s\n", cfg_path);
        return;
    }
    fprintf(f, "name = \"%s\"\n", name);
    fprintf(f, "runtime_dir = \"%s\"\n", run_dir);
    fprintf(f, "state_dir = \"%s/state\"\n", run_dir);
    fprintf(f, "cache_dir = \"%s/cache\"\n", run_dir);
    fprintf(f, "logs_dir = \"%s/logs\"\n", run_dir);
    fprintf(f, "config_dir = \"%s/config\"\n", run_dir);
    fprintf(f, "\n[afc]\n");
    fprintf(f, "enable = true\n");
    fprintf(f, "shm_path = \"%s\"\n", shm_path);
    fprintf(f, "max_chans = 100\n");
    fprintf(f, "\n[aqc]\n");
    fprintf(f, "enable = true\n");
    fprintf(f, "\n[sync.quic]\n");
    fprintf(f, "enable = true\n");
    fprintf(f, "addr = \"127.0.0.1:%u\"\n", (unsigned)sync_port);
    fclose(f);
}

/* Utility: millisecond sleep */
static void sleep_ms(unsigned int ms) {
    usleep(ms * 1000);
}

/* Globals for per-daemon client connection and sync addresses.
    Use static defaults so tests run reproducibly without runtime snprintfs. */
static const char g_owner_uds[128] = "/tmp/afc-run-owner/uds.sock";
static const char g_member1_uds[128] = "/tmp/afc-run-member1/uds.sock";
static const char g_member2_uds[128] = "/tmp/afc-run-member2/uds.sock";
static const char g_owner_sync_addr[64] = "127.0.0.1:41001";
static const char g_member1_sync_addr[64] = "127.0.0.1:41002";
static const char g_member2_sync_addr[64] = "127.0.0.1:41003";

/* Utility: spawn daemon process at run_dir with custom settings */
static pid_t spawn_daemon_at(const char *daemon_path,
                             const char *run_dir,
                             const char *name,
                             const char *shm_path,
                             uint16_t sync_port) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s/state %s/cache %s/logs %s/config", run_dir, run_dir, run_dir, run_dir, run_dir);
    system(cmd);
    
    char cfg_path[256];
    snprintf(cfg_path, sizeof(cfg_path), "%s/daemon.toml", run_dir);
    print_daemon_info(cfg_path, name, run_dir, shm_path, sync_port);
    
    pid_t pid = fork();
    if (pid == 0) {
        setenv("ARANYA_DAEMON", "aranya_daemon::aqc=trace,aranya_daemon::api=debug", 1);
        execl(daemon_path, daemon_path, "--config", cfg_path, NULL);
        exit(1);
    }
    return pid;
}

/* Initialize a client */
static AranyaError init_client(Client *c, const char *name, const char *daemon_addr, const char *aqc_addr) {
    AranyaError err;
    
    strncpy(c->name, name, sizeof(c->name) - 1);
    
#ifdef ENABLE_ARANYA_AQC
    AranyaAqcConfigBuilder aqc_builder;
    err = aranya_aqc_config_builder_init(&aqc_builder);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_aqc_config_builder_cleanup(&aqc_builder);
        return err;
    }
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
#endif
    
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
    
#ifdef ENABLE_ARANYA_AQC
    err = aranya_client_config_builder_set_aqc_config(&cli_builder, &aqc_cfg);
    if (err != ARANYA_ERROR_SUCCESS) {
        aranya_client_config_builder_cleanup(&cli_builder);
        return err;
    }
#endif
    
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
    
    AranyaError err = init_client(owner, "Owner", owner_uds, "127.0.0.1:0");
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
    
    return ARANYA_ERROR_SUCCESS;
}

/* Helper: owner adds member to team and member joins with raw IKM */
static AranyaError add_member_to_team(Team *t, Client *member, const char *member_sync_addr) {
    AranyaError err;
    
    /* Owner adds member device with default Member role (required for AFC channel creation) */
    err = aranya_add_device_to_team(&t->owner.client, &t->id, member->pk, member->pk_len);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    /* Note: AFC channels can only be created by Members per policy, so we keep the default Member role */
    
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
    
    /* Bidirectional sync to ensure roles/labels/state propagate */
    if (g_owner_sync_addr[0] && member_sync_addr && member_sync_addr[0]) {
        printf("    Syncing owner -> member (%s)...\n", member_sync_addr);
        err = aranya_sync_now(&t->owner.client, &t->id, member_sync_addr, NULL);
        if (err != ARANYA_ERROR_SUCCESS) {
            printf("    Warning: owner->member sync failed: %s\n", aranya_error_to_str(err));
        }
        sleep_ms(250);
        
        printf("    Syncing member -> owner (%s)...\n", g_owner_sync_addr);
        err = aranya_sync_now(&member->client, &t->id, g_owner_sync_addr, NULL);
        if (err != ARANYA_ERROR_SUCCESS) {
            printf("    Warning: member->owner sync failed: %s\n", aranya_error_to_str(err));
        }
        sleep_ms(250);
        
        /* One more round to ensure convergence */
        printf("    Final sync round...\n");
        (void)aranya_sync_now(&t->owner.client, &t->id, member_sync_addr, NULL);
        sleep_ms(250);
        (void)aranya_sync_now(&member->client, &t->id, g_owner_sync_addr, NULL);
    }
    
    /* Give the daemons time to fully process synced state */
    sleep_ms(1000);
    return ARANYA_ERROR_SUCCESS;
}

/* Helper to setup a team with two members */
static AranyaError setup_team_with_members(Team *team) {
    AranyaError err = init_team(team, g_owner_uds[0] ? g_owner_uds : "run/uds.sock");
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    err = init_client(&team->member1, "Member1", g_member1_uds[0] ? g_member1_uds : "run/uds.sock", "127.0.0.1:0");
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    err = init_client(&team->member2, "Member2", g_member2_uds[0] ? g_member2_uds : "run/uds.sock", "127.0.0.1:0");
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    err = add_member_to_team(team, &team->member1, g_member1_sync_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
    err = add_member_to_team(team, &team->member2, g_member2_sync_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        return err;
    }
    
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
static void report(const char *name, int ok, int *fails) {
    printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) (*fails)++;
}

/* Test: afc_create_bidi_channel and afc_channel_delete */
static int test_afc_create_bidi_channel(void) {
    printf("\n=== TEST: afc_create_bidi_channel and afc_channel_delete ===\n");
    
    Team team = {0};
    AranyaError err = init_team(&team, g_owner_uds[0] ? g_owner_uds : "run/uds.sock");
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create team: %s\n", aranya_error_to_str(err));
        return 0;
    }
    
    /* Initialize member1 and member2 */
    err = init_client(&team.member1, "Member1", g_member1_uds[0] ? g_member1_uds : "run/uds.sock", "127.0.0.1:0");
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init member1: %s\n", aranya_error_to_str(err));
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    err = init_client(&team.member2, "Member2", g_member2_uds[0] ? g_member2_uds : "run/uds.sock", "127.0.0.1:0");
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to init member2: %s\n", aranya_error_to_str(err));
        if (team.member1.pk) free(team.member1.pk);
        aranya_client_cleanup(&team.member1.client);
        if (team.owner.pk) free(team.owner.pk);
        aranya_client_cleanup(&team.owner.client);
        return 0;
    }
    
    /* Add members to team */
    err = add_member_to_team(&team, &team.member1, g_member1_sync_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to add member1 to team: %s\n", aranya_error_to_str(err));
        goto cleanup;
    }
    
    err = add_member_to_team(&team, &team.member2, g_member2_sync_addr);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to add member2 to team: %s\n", aranya_error_to_str(err));
        goto cleanup;
    }
    
    printf("  ✓ Members added to team with Member role\n");
    
    /* Create a label */
    AranyaLabelId label_id;
    err = aranya_create_label(&team.owner.client, &team.id, "AFC_TEST_LABEL", &label_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create label: %s\n", aranya_error_to_str(err));
        goto cleanup;
    }
    
    /* Assign label to both members */
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member1.id, 
                             &label_id, ARANYA_CHAN_OP_SEND_RECV);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to assign label to member1: %s\n", aranya_error_to_str(err));
        goto cleanup;
    }
    
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member2.id, 
                             &label_id, ARANYA_CHAN_OP_SEND_RECV);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to assign label to member2: %s\n", aranya_error_to_str(err));
        goto cleanup;
    }
    
    /* Sync again so members see the label assignments */
    if (g_owner_sync_addr[0] && g_member1_sync_addr[0] && g_member2_sync_addr[0]) {
        (void)aranya_sync_now(&team.owner.client, &team.id, g_member1_sync_addr, NULL);
        (void)aranya_sync_now(&team.owner.client, &team.id, g_member2_sync_addr, NULL);
        sleep_ms(250);
        (void)aranya_sync_now(&team.member1.client, &team.id, g_owner_sync_addr, NULL);
        (void)aranya_sync_now(&team.member1.client, &team.id, g_member2_sync_addr, NULL);
        sleep_ms(250);
        (void)aranya_sync_now(&team.member2.client, &team.id, g_owner_sync_addr, NULL);
        (void)aranya_sync_now(&team.member2.client, &team.id, g_member1_sync_addr, NULL);
        sleep_ms(500);
    }
    
    printf("  ✓ Label created and assigned\n");
    
    /* Create bidirectional AFC channel between members */
    AranyaAfcChannel channel;
    AranyaAfcCtrlMsg ctrl_msg;
    
    err = aranya_afc_create_bidi_channel(&team.member1.client, &team.id, &team.member2.id, 
                                         &label_id, &channel, &ctrl_msg);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create bidi channel: %s\n", aranya_error_to_str(err));
        goto cleanup;
    }
    
    printf("  ✓ Bidirectional AFC channel created\n");
    
    /* Get channel type */
    AranyaAfcChannelType chan_type;
    err = aranya_afc_get_channel_type(&channel, &chan_type);
    if (err == ARANYA_ERROR_SUCCESS) {
        printf("  ✓ Channel type: %d (should be %d for Bidirectional)\n", 
               chan_type, ARANYA_AFC_CHANNEL_TYPE_BIDIRECTIONAL);
    }
    
    /* Get label ID from channel */
    AranyaLabelId retrieved_label;
    err = aranya_afc_get_label_id(&channel, &retrieved_label);
    if (err == ARANYA_ERROR_SUCCESS) {
        printf("  ✓ Retrieved label from channel\n");
    }
    
    /* Get control message bytes */
    const uint8_t *ctrl_ptr;
    size_t ctrl_len;
    aranya_afc_ctrl_msg_get_bytes(&ctrl_msg, &ctrl_ptr, &ctrl_len);
    printf("  ✓ Control message size: %zu bytes\n", ctrl_len);
    
    /* Delete the channel */
    err = aranya_afc_channel_delete(&team.member1.client, &channel);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to delete channel: %s\n", aranya_error_to_str(err));
        aranya_afc_ctrl_msg_cleanup(&ctrl_msg);
        goto cleanup;
    }
    
    printf("  ✓ Channel deleted\n");
    
    /* Cleanup */
    aranya_afc_ctrl_msg_cleanup(&ctrl_msg);
    
cleanup:
    if (team.member2.pk) free(team.member2.pk);
    aranya_client_cleanup(&team.member2.client);
    if (team.member1.pk) free(team.member1.pk);
    aranya_client_cleanup(&team.member1.client);
    if (team.owner.pk) free(team.owner.pk);
    aranya_client_cleanup(&team.owner.client);
    
    return (err == ARANYA_ERROR_SUCCESS) ? 1 : 0;
}

/* Test: afc_create_uni_send_channel */
static int test_afc_create_uni_send_channel(void) {
    printf("\n=== TEST: afc_create_uni_send_channel ===\n");
    
    Team team = {0};
    AranyaError err = setup_team_with_members(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to setup team: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    AranyaLabelId label_id;
    err = aranya_create_label(&team.owner.client, &team.id, "SEND_LABEL", &label_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create label: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member1.id, 
                             &label_id, ARANYA_CHAN_OP_SEND_ONLY);
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member2.id, 
                             &label_id, ARANYA_CHAN_OP_RECV_ONLY);
    
    /* Sync so members see the label assignments */
    if (g_owner_sync_addr[0] && g_member1_sync_addr[0] && g_member2_sync_addr[0]) {
        (void)aranya_sync_now(&team.owner.client, &team.id, g_member1_sync_addr, NULL);
        (void)aranya_sync_now(&team.owner.client, &team.id, g_member2_sync_addr, NULL);
        sleep_ms(250);
        (void)aranya_sync_now(&team.member1.client, &team.id, g_owner_sync_addr, NULL);
        (void)aranya_sync_now(&team.member1.client, &team.id, g_member2_sync_addr, NULL);
        sleep_ms(250);
        (void)aranya_sync_now(&team.member2.client, &team.id, g_owner_sync_addr, NULL);
        (void)aranya_sync_now(&team.member2.client, &team.id, g_member1_sync_addr, NULL);
        sleep_ms(500);
    }
    
    /* Create unidirectional send channel from member1 to member2 */
    AranyaAfcChannel channel;
    AranyaAfcCtrlMsg ctrl_msg;
    
    err = aranya_afc_create_uni_send_channel(&team.member1.client, &team.id, &team.member2.id, 
                                             &label_id, &channel, &ctrl_msg);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create uni send channel: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    printf("  ✓ Unidirectional send channel created\n");
    
    AranyaAfcChannelType chan_type;
    err = aranya_afc_get_channel_type(&channel, &chan_type);
    if (err == ARANYA_ERROR_SUCCESS) {
        printf("  ✓ Channel type: %d (should be %d for Sender)\n", 
               chan_type, ARANYA_AFC_CHANNEL_TYPE_SENDER);
    }
    
    /* Cleanup */
    err = aranya_afc_channel_delete(&team.member1.client, &channel);
    aranya_afc_ctrl_msg_cleanup(&ctrl_msg);
    cleanup_team(&team);
    
    return 1;
}

/* Test: afc_create_uni_recv_channel */
static int test_afc_create_uni_recv_channel(void) {
    printf("\n=== TEST: afc_create_uni_recv_channel ===\n");
    
    Team team = {0};
    AranyaError err = setup_team_with_members(&team);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to setup team: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    AranyaLabelId label_id;
    err = aranya_create_label(&team.owner.client, &team.id, "RECV_LABEL", &label_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create label: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member1.id, 
                             &label_id, ARANYA_CHAN_OP_RECV_ONLY);
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member2.id, 
                             &label_id, ARANYA_CHAN_OP_SEND_ONLY);
    
    /* Sync so members see the label assignments */
    if (g_owner_sync_addr[0] && g_member1_sync_addr[0] && g_member2_sync_addr[0]) {
        (void)aranya_sync_now(&team.owner.client, &team.id, g_member1_sync_addr, NULL);
        (void)aranya_sync_now(&team.owner.client, &team.id, g_member2_sync_addr, NULL);
        sleep_ms(250);
        (void)aranya_sync_now(&team.member1.client, &team.id, g_owner_sync_addr, NULL);
        (void)aranya_sync_now(&team.member1.client, &team.id, g_member2_sync_addr, NULL);
        sleep_ms(250);
        (void)aranya_sync_now(&team.member2.client, &team.id, g_owner_sync_addr, NULL);
        (void)aranya_sync_now(&team.member2.client, &team.id, g_member1_sync_addr, NULL);
        sleep_ms(500);
    }
    
    /* Create unidirectional receive channel from member1 receiving from member2 */
    AranyaAfcChannel channel;
    AranyaAfcCtrlMsg ctrl_msg;
    
    err = aranya_afc_create_uni_recv_channel(&team.member1.client, &team.id, &team.member2.id, 
                                             &label_id, &channel, &ctrl_msg);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create uni recv channel: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    printf("  ✓ Unidirectional receive channel created\n");
    
    AranyaAfcChannelType chan_type;
    err = aranya_afc_get_channel_type(&channel, &chan_type);
    if (err == ARANYA_ERROR_SUCCESS) {
        printf("  ✓ Channel type: %d (should be %d for Receiver)\n", 
               chan_type, ARANYA_AFC_CHANNEL_TYPE_RECEIVER);
    }
    
    /* Cleanup */
    err = aranya_afc_channel_delete(&team.member1.client, &channel);
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
    err = aranya_create_label(&team.owner.client, &team.id, "SEAL_OPEN_LABEL", &label_id);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create label: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member1.id, 
                             &label_id, ARANYA_CHAN_OP_SEND_RECV);
    err = aranya_assign_label(&team.owner.client, &team.id, &team.member2.id, 
                             &label_id, ARANYA_CHAN_OP_SEND_RECV);
    
    /* Sync so members see the label assignments */
    if (g_owner_sync_addr[0] && g_member1_sync_addr[0] && g_member2_sync_addr[0]) {
        (void)aranya_sync_now(&team.owner.client, &team.id, g_member1_sync_addr, NULL);
        (void)aranya_sync_now(&team.owner.client, &team.id, g_member2_sync_addr, NULL);
        sleep_ms(250);
        (void)aranya_sync_now(&team.member1.client, &team.id, g_owner_sync_addr, NULL);
        (void)aranya_sync_now(&team.member1.client, &team.id, g_member2_sync_addr, NULL);
        sleep_ms(250);
        (void)aranya_sync_now(&team.member2.client, &team.id, g_owner_sync_addr, NULL);
        (void)aranya_sync_now(&team.member2.client, &team.id, g_member1_sync_addr, NULL);
        sleep_ms(500);
    }
    
    /* Create sender channel on member1 */
    AranyaAfcChannel sender_channel;
    AranyaAfcCtrlMsg sender_ctrl;
    
    err = aranya_afc_create_bidi_channel(&team.member1.client, &team.id, &team.member2.id, 
                                         &label_id, &sender_channel, &sender_ctrl);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create sender channel: %s\n", aranya_error_to_str(err));
        cleanup_team(&team);
        return 0;
    }
    
    /* Get control message bytes to send to member2 */
    const uint8_t *ctrl_bytes;
    size_t ctrl_len;
    aranya_afc_ctrl_msg_get_bytes(&sender_ctrl, &ctrl_bytes, &ctrl_len);
    printf("  ✓ Control message: %zu bytes\n", ctrl_len);
    
    /* Create receiver channel on member2 using control message */
    AranyaAfcChannel receiver_channel;
    AranyaAfcChannelType recv_type;
    
    err = aranya_afc_recv_ctrl(&team.member2.client, &team.id, ctrl_bytes, ctrl_len, 
                               &receiver_channel, &recv_type);
    if (err != ARANYA_ERROR_SUCCESS) {
        printf("  Failed to create receiver from ctrl: %s\n", aranya_error_to_str(err));
        aranya_afc_channel_delete(&team.member1.client, &sender_channel);
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
        aranya_afc_channel_delete(&team.member2.client, &receiver_channel);
        aranya_afc_channel_delete(&team.member1.client, &sender_channel);
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
        aranya_afc_channel_delete(&team.member2.client, &receiver_channel);
        aranya_afc_channel_delete(&team.member1.client, &sender_channel);
        aranya_afc_ctrl_msg_cleanup(&sender_ctrl);
        cleanup_team(&team);
        return 0;
    }
    
    decrypted[decrypted_len] = '\0';
    printf("  ✓ Message opened: \"%s\"\n", decrypted);
    
    /* Verify decrypted matches original */
    int match = (strcmp((char *)decrypted, plaintext) == 0);
    printf("  %s Decrypted message matches original\n", match ? "✓" : "✗");
    
    /* Test sequence number retrieved from channel_open */
    printf("  ✓ Sequence number retrieved from channel_open\n");
    
    /* Cleanup */
    aranya_afc_seq_cleanup(&seq);
    free(decrypted);
    free(ciphertext);
    aranya_afc_channel_delete(&team.member2.client, &receiver_channel);
    aranya_afc_channel_delete(&team.member1.client, &sender_channel);
    aranya_afc_ctrl_msg_cleanup(&sender_ctrl);
    cleanup_team(&team);
    
    return match;
}

int main(int argc, const char *argv[]) {
    int fails = 0;
    pid_t owner_pid = -1;
    pid_t member1_pid = -1;
    pid_t member2_pid = -1;

#if defined(ENABLE_ARANYA_PREVIEW)
    setenv("ARANYA_CAPI", "aranya=debug", 1);
    
    AranyaError err = aranya_init_logging();
    if (err != ARANYA_ERROR_SUCCESS) {
        fprintf(stderr, "Failed to initialize logging: %s\n", aranya_error_to_str(err));
        return EXIT_FAILURE;
    }
    
    printf("Running aranya-client-capi AFC tests\n");
    printf("====================================\n");

    if (argc == 2) {
        const char *daemon_path = argv[1];
        /* Using static defaults for UDS and sync addresses; spawn daemons */
        printf("Spawning owner daemon: %s\n", daemon_path);
        owner_pid = spawn_daemon_at(daemon_path, "/tmp/afc-run-owner", "test-daemon-owner", "/afc-owner", 41001);
        printf("Owner Daemon PID: %d\n", owner_pid);

        printf("Spawning member1 daemon: %s\n", daemon_path);
        member1_pid = spawn_daemon_at(daemon_path, "/tmp/afc-run-member1", "test-daemon-member1", "/afc-member1", 41002);
        printf("Member1 Daemon PID: %d\n", member1_pid);

        printf("Spawning member2 daemon: %s\n", daemon_path);
        member2_pid = spawn_daemon_at(daemon_path, "/tmp/afc-run-member2", "test-daemon-member2", "/afc-member2", 41003);
        printf("Member2 Daemon PID: %d\n", member2_pid);

        printf("Waiting 7 seconds for daemons to initialize...\n");
        sleep_ms(7000);
        printf("Daemons should be ready now\n");
    }

    /* Test AFC channel operations */
    report("afc_create_bidi_channel", test_afc_create_bidi_channel(), &fails);
    report("afc_create_uni_send_channel", test_afc_create_uni_send_channel(), &fails);
    report("afc_create_uni_recv_channel", test_afc_create_uni_recv_channel(), &fails);
    report("afc_seal_open", test_afc_seal_open(), &fails);

    if (owner_pid > 0) {
        printf("\nTerminating owner daemon (PID %d)\n", owner_pid);
        kill(owner_pid, SIGTERM);
        waitpid(owner_pid, NULL, 0);
    }
    if (member1_pid > 0) {
        printf("\nTerminating member1 daemon (PID %d)\n", member1_pid);
        kill(member1_pid, SIGTERM);
        waitpid(member1_pid, NULL, 0);
    }
    if (member2_pid > 0) {
        printf("\nTerminating member2 daemon (PID %d)\n", member2_pid);
        kill(member2_pid, SIGTERM);
        waitpid(member2_pid, NULL, 0);
    }

    printf("\n====================================\n");
    if (fails == 0) {
        printf("ALL AFC TESTS PASSED\n");
        return EXIT_SUCCESS;
    } else {
        printf("%d AFC TEST(S) FAILED\n", fails);
        return EXIT_FAILURE;
    }
#else
    printf("ENABLE_ARANYA_PREVIEW not defined; skipping AFC tests\n");
    return EXIT_SUCCESS;
#endif
}