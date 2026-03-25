#![allow(clippy::panic)]
use std::{panic, sync::Arc};

use aranya_crypto::{
    default::{DefaultCipherSuite, DefaultEngine},
    Rng,
};
use backon::{ExponentialBuilder, Retryable as _};
use tokio::{
    net::{UnixListener, UnixStream},
    task::JoinSet,
};
use tokio_stream::wrappers::UnixListenerStream;

use super::*;
use crate::crypto::ApiKey;

impl<CS: CipherSuite, R> ClientConn<CS, R> {
    fn force_rekey(&mut self) {
        self.ctx = None;
    }
}

type CS = DefaultCipherSuite;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Ping {
    v: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Pong {
    v: usize,
}

/// Basic one client, one server ping pong test.
#[tokio::test(flavor = "multi_thread")]
async fn test_ping_pong() {
    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().to_path_buf().join("sock"));
    let info = Arc::from(path.as_os_str().as_encoded_bytes());

    let (eng, _) = DefaultEngine::from_entropy(Rng);
    let sk = ApiKey::<CS>::new(&eng);
    let pk = sk.public().unwrap();

    const MAX_PING_PONGS: usize = 100;

    let mut set = JoinSet::new();

    {
        let path = Arc::clone(&path);
        let info = Arc::clone(&info);
        set.spawn(async move {
            let listener = UnixListener::bind(&*path)?;
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(usize::MAX)
                .new_codec();
            let mut server = server(UnixListenerStream::new(listener), codec, sk, &info);

            let mut conn = server.accept().await.unwrap()?;
            for v in 0..MAX_PING_PONGS {
                let got: Ping = conn.recv().await?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "stream finished early")
                })?;
                assert_eq!(got, Ping { v });
                conn.send(Pong {
                    v: got.v.wrapping_add(1),
                })
                .await?;
            }
            io::Result::Ok(())
        });
    }

    {
        let path = Arc::clone(&path);
        let info = Arc::clone(&info);
        set.spawn(async move {
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(usize::MAX)
                .new_codec();
            let sock = (|| UnixStream::connect(&*path))
                .retry(ExponentialBuilder::default())
                .await
                .unwrap();
            let mut client = client(sock, codec, Rng, pk, &info);
            for v in 0..MAX_PING_PONGS {
                client.send(Ping { v }).await?;
                let got: Pong = client.recv().await?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "stream finished early")
                })?;
                let want = Pong {
                    v: v.wrapping_add(1),
                };
                assert_eq!(got, want)
            }
            Ok(())
        });
    }

    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                set.abort_all();
                panic!("{err}");
            }
            Err(err) if err.is_panic() => panic::resume_unwind(err.into_panic()),
            Err(err) => panic!("{err}"),
        }
    }
}

/// One client rekeys each request.
#[tokio::test(flavor = "multi_thread")]
async fn test_rekey() {
    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().to_path_buf().join("sock"));
    let info = Arc::from(path.as_os_str().as_encoded_bytes());

    let (eng, _) = DefaultEngine::from_entropy(Rng);
    let sk = ApiKey::<CS>::new(&eng);
    let pk = sk.public().unwrap();

    const MAX_PING_PONGS: usize = 100;

    let mut set = JoinSet::new();

    {
        let path = Arc::clone(&path);
        let info = Arc::clone(&info);
        set.spawn(async move {
            let listener = UnixListener::bind(&*path).unwrap();
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(usize::MAX)
                .new_codec();
            let mut server = server(UnixListenerStream::new(listener), codec.clone(), sk, &info);
            let mut conn = server.accept().await.unwrap().unwrap();
            for v in 0..MAX_PING_PONGS {
                let got: Ping = conn.recv().await?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "stream finished early")
                })?;
                // In this test the client rekeys each time
                // it sends data, so our seq number should
                // always be zero.
                let ctx = conn.ctx.as_ref().map(|ctx| &ctx.seal).unwrap();
                assert_eq!(ctx.seq(), Seq::ZERO);

                assert_eq!(got, Ping { v });
                conn.send(Pong {
                    v: got.v.wrapping_add(1),
                })
                .await?;

                // Double check that it actually increments.
                let ctx = conn.ctx.as_ref().map(|ctx| &ctx.seal).unwrap();
                assert_eq!(ctx.seq(), Seq::new(1));
            }
            io::Result::Ok(())
        });
    }

    {
        let path = Arc::clone(&path);
        let info = Arc::clone(&info);
        set.spawn(async move {
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(usize::MAX)
                .new_codec();
            let sock = (|| UnixStream::connect(&*path))
                .retry(ExponentialBuilder::default())
                .await
                .unwrap();
            let mut client = client(sock, codec, Rng, pk, &info);
            for v in 0..MAX_PING_PONGS {
                let last = client.rekeys;
                client.force_rekey();
                client.send(Ping { v }).await.unwrap();
                assert_eq!(client.rekeys, last + 1);
                let got: Pong = client.recv().await?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "stream finished early")
                })?;
                let want = Pong {
                    v: v.wrapping_add(1),
                };
                assert_eq!(got, want)
            }
            Ok(())
        });
    }

    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                set.abort_all();
                panic!("{err}");
            }
            Err(err) if err.is_panic() => panic::resume_unwind(err.into_panic()),
            Err(err) => panic!("{err}"),
        }
    }
}

/// N clients make repeated requests to one server.
#[tokio::test(flavor = "multi_thread")]
async fn test_multi_client() {
    let dir = tempfile::tempdir().unwrap();
    let path = Arc::new(dir.path().to_path_buf().join("sock"));
    let info = Arc::from(path.as_os_str().as_encoded_bytes());

    let (eng, _) = DefaultEngine::from_entropy(Rng);
    let sk = ApiKey::<CS>::new(&eng);
    let pk = sk.public().unwrap();

    const MAX_PING_PONGS: usize = 2;
    const MAX_CLIENTS: usize = 10;

    let mut set = JoinSet::new();

    {
        let path = Arc::clone(&path);
        let info = Arc::clone(&info);
        set.spawn(async move {
            let listener = UnixListener::bind(&*path).unwrap();
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(usize::MAX)
                .new_codec();
            let mut server = server(UnixListenerStream::new(listener), codec.clone(), sk, &info);
            let mut set = JoinSet::new();
            for _ in 0..MAX_CLIENTS {
                let mut conn = server.accept().await.unwrap()?;
                set.spawn(async move {
                    for v in 0..MAX_PING_PONGS {
                        let got: Ping = conn.recv().await?.ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "client stream finished early",
                            )
                        })?;
                        assert_eq!(got, Ping { v });
                        conn.send(Pong {
                            v: got.v.wrapping_add(1),
                        })
                        .await?;
                    }
                    io::Result::Ok(())
                });
            }
            set.join_all()
                .await
                .into_iter()
                .find(|v| v.is_err())
                .unwrap_or(Ok(()))
        });
    }

    for _ in 0..10 {
        let path = Arc::clone(&path);
        let info = Arc::clone(&info);
        let pk = pk.clone();
        set.spawn(async move {
            let codec = LengthDelimitedCodec::builder()
                .max_frame_length(usize::MAX)
                .new_codec();
            let sock = (|| UnixStream::connect(&*path))
                .retry(ExponentialBuilder::default())
                .await
                .unwrap();
            let mut client = client(sock, codec, Rng, pk, &info);
            for v in 0..MAX_PING_PONGS {
                client.send(Ping { v }).await?;
                let got: Pong = client.recv().await?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "server stream finished early")
                })?;
                let want = Pong {
                    v: v.wrapping_add(1),
                };
                assert_eq!(got, want);
            }
            Ok(())
        });
    }

    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                set.abort_all();
                panic!("{err}");
            }
            Err(err) if err.is_panic() => panic::resume_unwind(err.into_panic()),
            Err(err) => panic!("{err}"),
        }
    }
}
