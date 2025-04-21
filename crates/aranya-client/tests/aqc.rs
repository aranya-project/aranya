use std::{
    net::{Ipv4Addr, SocketAddr},
    ops::DerefMut as _,
    sync::Arc,
    time::Duration,
};

mod common;
use anyhow::Result;
use aranya_client::{
    aqc_net::{run_channels, AqcChannelType, AqcClient},
    SyncPeerConfig,
};
use aranya_crypto::csprng::rand;
use aranya_daemon_api::{ChanOp, LabelId, NetIdentifier, Role};
use aranya_runtime::{
    protocol::{TestActions, TestEngine, TestSink},
    storage::memory::MemStorageProvider,
    ClientState,
};
use buggy::BugExt as _;
use bytes::Bytes;
use common::{sleep, TeamCtx};
use s2n_quic::{provider::congestion_controller::Bbr, Server};
use tempfile::tempdir;
use tokio::sync::{mpsc, Mutex as TMutex};
use tracing::{debug, info};

/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!("../src/cert.pem");
/// NOTE: this certificate is to be used for demonstration purposes only!
pub static KEY_PEM: &str = include_str!("../src/key.pem");

#[test_log::test(tokio::test)]
async fn test_aqc_channels() -> Result<()> {
    let client1 = make_client();
    let sink1 = Arc::new(TMutex::new(TestSink::new()));
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = ck.key_pair.serialize_pem();
    let cert = ck.cert.pem();

    let server1 = get_server(cert.clone(), key.clone())?;
    let (mut aqc_client1, sender1) = AqcClient::new(&*cert.clone())?;

    let _client2 = make_client();

    let _ = client1.lock().await.new_graph(
        &0u64.to_be_bytes(),
        TestActions::Init(0),
        sink1.lock().await.deref_mut(),
    )?;

    let _ = spawn_channel_listener(server1, sender1)?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server2 = get_server(cert.clone(), key)?;
    let (mut aqc_client2, sender2) = AqcClient::new(&*cert)?;
    let addr2 = spawn_channel_listener(server2, sender2)?;
    let mut channel1 = aqc_client1
        .create_bidirectional_channel(addr2, LabelId::default())
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut channel2 = match aqc_client2
        .receive_channel()
        .await
        .assume("channel must exist")?
    {
        AqcChannelType::Bidirectional { channel } => channel,
        _ => {
            buggy::bug!("Expected a bidirectional channel")
        }
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut send1_1 = channel1.create_unidirectional_stream().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut send1_2, mut recv1_2) = channel1.create_bidirectional_stream().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test sending streams

    // Send from 1 to 2 with a unidirectional stream
    let msg1 = Bytes::from("hello");
    send1_1.send(&msg1).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Receive a unidirectional stream from peer 1
    let mut recv2_1 = channel2
        .receive_unidirectional_stream()
        .await
        .assume("stream not received")?
        .assume("stream not received")?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut target = vec![0u8; 1024 * 1024 * 2];
    let len = recv2_1
        .receive(target.as_mut_slice())
        .await?
        .assume("no data received")?;
    assert_eq!(&target[..len], b"hello");

    // Send from 1 to 2 with a bidirectional stream
    let msg2 = Bytes::from("hello2");
    send1_2.send(&msg2).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut send2_2, mut recv2_2) = channel2
        .receive_bidirectional_stream()
        .await
        .assume("stream not received")?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut target = vec![0u8; 1024 * 1024 * 2];
    let len = recv2_2
        .receive(target.as_mut_slice())
        .await?
        .assume("no data received")?;
    assert_eq!(&target[..len], b"hello2");

    // Send from 2 to 1 with a bidirectional stream
    let msg3 = Bytes::from("hello3");
    send2_2.send(&msg3).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut target = vec![0u8; 1024 * 1024 * 2];
    let len = recv1_2
        .receive(target.as_mut_slice())
        .await?
        .assume("no data received")?;
    assert_eq!(&target[..len], b"hello3");

    // Test sending a large message
    let big_data = {
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; 1024 * 1024 * 3 / 2];
        rand::Rng::fill(&mut rng, &mut data[..]);
        Bytes::from(data)
    };

    send1_2.send(&big_data).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut total_len: usize = 0;
    let mut total_pieces: i32 = 0;
    // Send stream should return the message in pieces
    while let Some(len) = recv2_2.receive(&mut target[total_len..]).await? {
        total_pieces = total_pieces.checked_add(1).expect("Pieces overflow");
        total_len = total_len.checked_add(len).expect("Length overflow");
        if total_len >= big_data.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(total_pieces > 1);
    assert_eq!(total_len, big_data.len());
    assert_eq!(&target[..total_len], &big_data[..]);

    Ok(())
}

fn get_server(cert: String, key: String) -> Result<Server> {
    let server = Server::builder()
        .with_tls((&cert[..], &key[..]))?
        .with_io("127.0.0.1:0")?
        .with_congestion_controller(Bbr::default())?
        .start()?;
    Ok(server)
}

fn spawn_channel_listener(
    server: Server,
    sender: mpsc::Sender<AqcChannelType>,
) -> Result<SocketAddr> {
    let server_addr = server.local_addr()?;
    tokio::spawn(run_channels(server, sender));
    Ok(server_addr)
}

fn make_client() -> Arc<TMutex<ClientState<TestEngine, MemStorageProvider>>> {
    let engine = TestEngine::new();
    let storage = MemStorageProvider::new();

    Arc::new(TMutex::new(ClientState::new(engine, storage)))
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn test_aqc_chans() -> Result<()> {
    let interval = Duration::from_millis(100);
    let sync_config = SyncPeerConfig::builder().interval(interval).build()?;
    let sleep_interval = interval * 6;

    let tmp = tempdir()?;
    let work_dir = tmp.path().to_path_buf();

    let mut team = TeamCtx::new("test_aqc_one_way_two_chans".into(), work_dir).await?;

    // create team.
    let team_id = team
        .owner
        .client
        .create_team()
        .await
        .expect("expected to create team");
    info!(?team_id);
    // TODO: implement add_team.
    /*
    team.admin.client.add_team(team_id).await?;
    team.operator.client.add_team(team_id).await?;
    team.membera.client.add_team(team_id).await?;
    team.memberb.client.add_team(team_id).await?;
    */

    // get sync addresses.
    let owner_addr = team.owner.aranya_local_addr().await?;
    let admin_addr = team.admin.aranya_local_addr().await?;
    let operator_addr = team.operator.aranya_local_addr().await?;
    let membera_addr = team.membera.aranya_local_addr().await?;
    let memberb_addr = team.memberb.aranya_local_addr().await?;

    // setup sync peers.
    let mut owner_team = team.owner.client.team(team_id);
    let mut admin_team = team.admin.client.team(team_id);
    let mut operator_team = team.operator.client.team(team_id);
    let mut membera_team = team.membera.client.team(team_id);
    let mut memberb_team = team.memberb.client.team(team_id);

    owner_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    owner_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    admin_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    admin_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    operator_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    operator_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    operator_team
        .add_sync_peer(membera_addr.into(), sync_config.clone())
        .await?;

    membera_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    membera_team
        .add_sync_peer(memberb_addr.into(), sync_config.clone())
        .await?;

    memberb_team
        .add_sync_peer(owner_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(admin_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(operator_addr.into(), sync_config.clone())
        .await?;
    memberb_team
        .add_sync_peer(membera_addr.into(), sync_config)
        .await?;

    // add admin to team.
    info!("adding admin to team");
    owner_team.add_device_to_team(team.admin.pk.clone()).await?;
    owner_team.assign_role(team.admin.id, Role::Admin).await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add operator to team.
    info!("adding operator to team");
    owner_team
        .add_device_to_team(team.operator.pk.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    admin_team
        .assign_role(team.operator.id, Role::Operator)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // add membera to team.
    info!("adding membera to team");
    operator_team
        .add_device_to_team(team.membera.pk.clone())
        .await?;

    // add memberb to team.
    info!("adding memberb to team");
    operator_team
        .add_device_to_team(team.memberb.pk.clone())
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // get aqc addresses.
    // TODO: use aqc_local_addr()
    let membera_aqc_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 8000);
    let memberb_aqc_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 8001);

    // TODO: use aqc addr
    operator_team
        .assign_aqc_net_identifier(team.membera.id, NetIdentifier(membera_aqc_addr.to_string()))
        .await?;
    operator_team
        .assign_aqc_net_identifier(team.memberb.id, NetIdentifier(memberb_aqc_addr.to_string()))
        .await?;

    let membera_addr = run_aqc_server(
        membera_aqc_addr,
        team.membera.client.aqc().get_client_sender(),
    )?;
    let memberb_addr = run_aqc_server(
        memberb_aqc_addr,
        team.memberb.client.aqc().get_client_sender(),
    )?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // fact database queries
    let mut queries = team.membera.client.queries(team_id);
    let devices = queries.devices_on_team().await?;
    assert_eq!(devices.iter().count(), 5);
    debug!("membera devices on team: {:?}", devices.iter().count());
    let role = queries.device_role(team.membera.id).await?;
    assert_eq!(role, Role::Member);
    debug!("membera role: {:?}", role);
    let keybundle = queries.device_keybundle(team.membera.id).await?;
    debug!("membera keybundle: {:?}", keybundle);

    let aqc_net_identifier = queries
        .aqc_net_identifier(team.membera.id)
        .await?
        .expect("expected net identifier");
    assert_eq!(
        aqc_net_identifier,
        NetIdentifier(membera_aqc_addr.to_string())
    );
    debug!("membera aqc_net_identifer: {:?}", aqc_net_identifier);

    // wait for ctrl message to be sent.
    sleep(Duration::from_millis(100)).await;

    let label1 = operator_team.create_label("label1".to_string()).await?;
    let op = ChanOp::SendRecv;
    operator_team
        .assign_label(team.membera.id, label1, op)
        .await?;
    operator_team
        .assign_label(team.memberb.id, label1, op)
        .await?;

    // wait for syncing.
    sleep(sleep_interval).await;

    // membera creates aqc bidi channel with memberb
    let (mut bidi_chan1, aqc_bidi_ctrl) = team
        .membera
        .client
        .aqc()
        .create_bidi_channel(
            team_id,
            NetIdentifier(memberb_aqc_addr.to_string()),
            NetIdentifier(memberb_addr.to_string()),
            label1,
        )
        .await?;
    // memberb received aqc bidi channel ctrl message
    // TODO: receiving AQC ctrl messages will happen via the network.
    team.memberb
        .client
        .aqc()
        .receive_aqc_ctrl(team_id, aqc_bidi_ctrl)
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let channel_type = team
        .memberb
        .client
        .aqc()
        .receive_channel()
        .await
        .assume("channel must exist")?;
    let mut bidi_chan2 = match channel_type {
        AqcChannelType::Bidirectional { channel } => channel,
        _ => {
            buggy::bug!("Expected a bidirectional channel")
        }
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut send1_1 = bidi_chan1.create_unidirectional_stream().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut send1_2, mut recv1_2) = bidi_chan1.create_bidirectional_stream().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Test sending streams

    // Send from 1 to 2 with a unidirectional stream
    let msg1 = Bytes::from("hello");
    send1_1.send(&msg1).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Receive a unidirectional stream from peer 1
    let mut recv2_1 = bidi_chan2
        .receive_unidirectional_stream()
        .await
        .assume("stream not received")?
        .assume("stream not received")?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut target = vec![0u8; 1024 * 1024 * 2];
    let len = recv2_1
        .receive(target.as_mut_slice())
        .await?
        .assume("no data received")?;
    assert_eq!(&target[..len], b"hello");

    // Send from 1 to 2 with a bidirectional stream
    let msg2 = Bytes::from("hello2");
    send1_2.send(&msg2).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (mut send2_2, mut recv2_2) = bidi_chan2
        .receive_bidirectional_stream()
        .await
        .assume("stream not received")?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut target = vec![0u8; 1024 * 1024 * 2];
    let len = recv2_2
        .receive(target.as_mut_slice())
        .await?
        .assume("no data received")?;
    assert_eq!(&target[..len], b"hello2");

    // Send from 2 to 1 with a bidirectional stream
    let msg3 = Bytes::from("hello3");
    send2_2.send(&msg3).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut target = vec![0u8; 1024 * 1024 * 2];
    let len = recv1_2
        .receive(target.as_mut_slice())
        .await?
        .assume("no data received")?;
    assert_eq!(&target[..len], b"hello3");

    // Test sending a large message
    let big_data = {
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; 1024 * 1024 * 3 / 2];
        rand::Rng::fill(&mut rng, &mut data[..]);
        Bytes::from(data)
    };

    send1_2.send(&big_data).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut total_len: usize = 0;
    let mut total_pieces: i32 = 0;
    // Send stream should return the message in pieces
    while let Some(len) = recv2_2.receive(&mut target[total_len..]).await? {
        total_pieces = total_pieces.checked_add(1).expect("Pieces overflow");
        total_len = total_len.checked_add(len).expect("Length overflow");
        if total_len >= big_data.len() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(total_pieces > 1);
    assert_eq!(total_len, big_data.len());
    assert_eq!(&target[..total_len], &big_data[..]);

    Ok(())
}

fn run_aqc_server(
    aqc_addr: SocketAddr,
    sender: mpsc::Sender<AqcChannelType>,
) -> Result<SocketAddr> {
    let server = Server::builder()
        .with_tls((CERT_PEM, KEY_PEM))?
        // .with_io(aqc_addr)?
        .with_io("127.0.0.1:0")?
        .with_congestion_controller(Bbr::default())?
        .start()?;
    let addr = server.local_addr()?;
    tokio::spawn(run_channels(server, sender));
    Ok(addr)
}
