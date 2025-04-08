use std::{net::SocketAddr, ops::DerefMut as _, sync::Arc, time::Duration};

use anyhow::Result;
use aranya_client::aqc_net::{run_channels, AqcChannelType, AqcClient};
use aranya_crypto::csprng::rand;
use aranya_fast_channels::Label;
use aranya_runtime::{
    protocol::{TestActions, TestEngine, TestSink},
    storage::memory::MemStorageProvider,
    ClientState,
};
use buggy::BugExt as _;
use bytes::Bytes;
use s2n_quic::{provider::congestion_controller::Bbr, Server};
use tokio::sync::Mutex as TMutex;

#[test_log::test(tokio::test)]
async fn test_aqc_channels() -> Result<()> {
    let client1 = make_client();
    let sink1 = Arc::new(TMutex::new(TestSink::new()));
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let key = ck.key_pair.serialize_pem();
    let cert = ck.cert.pem();

    let server1 = get_server(cert.clone(), key.clone())?;
    let aqc_client1 = Arc::new(TMutex::new(AqcClient::new(&*cert.clone())?));

    let _client2 = make_client();

    let _ = client1.lock().await.new_graph(
        &0u64.to_be_bytes(),
        TestActions::Init(0),
        sink1.lock().await.deref_mut(),
    )?;

    let _ = spawn_channel_listener(aqc_client1.clone(), server1)?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server2 = get_server(cert.clone(), key)?;
    let aqc_client2 = Arc::new(TMutex::new(AqcClient::new(&*cert)?));
    let addr2 = spawn_channel_listener(aqc_client2.clone(), server2)?;
    let mut channel1 = aqc_client1
        .lock()
        .await
        .create_bidirectional_channel(addr2, Label::new(0))
        .await?;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut channel2 = match aqc_client2
        .lock()
        .await
        .receive_channel()
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
    aqc_client: Arc<TMutex<AqcClient>>,
    server: Server,
) -> Result<SocketAddr> {
    let server_addr = server.local_addr()?;
    tokio::spawn(run_channels(aqc_client, server));
    Ok(server_addr)
}

fn make_client() -> Arc<TMutex<ClientState<TestEngine, MemStorageProvider>>> {
    let engine = TestEngine::new();
    let storage = MemStorageProvider::new();

    Arc::new(TMutex::new(ClientState::new(engine, storage)))
}
