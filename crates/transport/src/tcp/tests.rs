use std::net::{Ipv4Addr, SocketAddrV4};

use anyhow::Result;
use test_log::test;
use tokio::task;
use tracing::info;

use super::client::TcpClient;
use crate::{is_transport, tcp::server::TcpTransport, Transport};

#[test]
fn test_tcp_client_implements_transport() -> Result<()> {
    is_transport::<TcpClient>();

    Ok(())
}

#[test]
fn test_tcp_implements_transport() -> Result<()> {
    is_transport::<TcpTransport>();

    Ok(())
}

#[test(tokio::test(flavor = "multi_thread"))]
async fn test_tcp_client_server() -> Result<()> {
    const NUM_CLIENTS: u8 = 10;
    const ANY: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);

    let (mut transport, mut server) = TcpTransport::new(ANY.into()).await?;

    let server_addr = server.local_addr()?;

    task::spawn(async move { server.run().await });

    let send_pong: Vec<u8> = "pong".into();

    let mut handles = Vec::new();

    handles.push(task::spawn(async move {
        info!("starting server");
        for _i in 0..NUM_CLIENTS {
            // recv ping.
            let mut recv_ping = vec![0u8; 5];
            info!("checking if server is readable");
            transport.readable().await.expect("readable");
            info!("server is readable");

            let addr = loop {
                let (n, addr) = transport
                    .try_recv_from(&mut recv_ping)
                    .await
                    .expect("recv data");
                if n > 0 {
                    info!("server received ping");
                    break addr;
                }
                info!("server retrying receive ping");
            };

            // send pong.
            info!(?addr, "server sending pong");
            transport
                .send_to(&send_pong, addr)
                .await
                .expect("send data");
            info!(?addr, "server sent pong");
        }
    }));

    for i in 0..NUM_CLIENTS {
        info!(?i, "starting client");
        handles.push(task::spawn(async move {
            let mut client = TcpClient::new().expect("client");

            let send_ping: Vec<u8> = format!("ping{:?}", i).into();
            let send_pong: Vec<u8> = "pong".into();

            // send ping.
            info!(?i, "client sending ping");
            client
                .send_to(&send_ping, server_addr)
                .await
                .expect("send data");

            // recv pong.
            info!(?i, "client waiting for pong");
            let mut recv_pong = vec![0u8; send_pong.len()];
            info!(?i, "checking if client is readable");
            client.readable().await.expect("readable");
            info!(?i, "client is readable");

            loop {
                let (n, _addr) = client
                    .try_recv_from(&mut recv_pong)
                    .await
                    .expect("receive data");
                if n > 0 {
                    break;
                }
            }
            info!(?i, "client received pong");
        }));
    }

    for handle in handles {
        handle.await.expect("error joining threads");
    }

    Ok(())
}
