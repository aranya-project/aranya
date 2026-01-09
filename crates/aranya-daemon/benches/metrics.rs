use std::net::Ipv4Addr;

use aranya_certgen::{
    generate_root_ca, generate_signed_cert, issuer_from_ca, write_cert, write_key, SubjectAltNames,
};
use aranya_daemon::{
    config::{Config, QuicSyncConfig, SyncConfig, Toggle},
    Daemon,
};
use aranya_util::Addr;
use divan::AllocProfiler;
use tokio::runtime::Runtime;

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

fn main() {
    divan::main();
}

// NOTE: divan currently requires sync functions to work, so we spawn a runtime and block on async.
/// Benchmarks how long the daemon takes to set itself up to be spawned.
#[divan::bench]
fn daemon_startup(bencher: divan::Bencher<'_, '_>) {
    bencher
        .with_inputs(|| {
            // Spawn a new dir that will live for one run, since we want to measure "cold boot" perf
            let tmp_dir = tempfile::tempdir().expect("We should be able to create directories");
            let rt = Runtime::new().expect("We need a tokio runtime");
            let work_dir = tmp_dir.path().to_path_buf();

            #[cfg(feature = "afc")]
            let shm_path = {
                let path = "/test_daemon_run\0"
                    .try_into()
                    .expect("should be able to parse AFC shared memory path");
                let _ = aranya_fast_channels::shm::unlink(&path);
                path
            };

            // Generate mTLS certificates
            let certs_dir = work_dir.join("certs");
            let root_certs_dir = certs_dir.join("root_certs");
            std::fs::create_dir_all(&root_certs_dir).expect("should create root_certs_dir");

            let (ca_cert, ca_key) = generate_root_ca("Bench CA", 365).expect("should generate CA");
            write_cert(root_certs_dir.join("ca.pem"), &ca_cert).expect("should write CA cert");

            let issuer = issuer_from_ca(&ca_cert, ca_key).expect("should create issuer");
            let san = SubjectAltNames {
                dns_names: vec!["bench.test.local".to_string()],
                ip_addresses: vec!["127.0.0.1".parse().expect("valid IP")],
            };
            let (device_cert, device_key) =
                generate_signed_cert("Bench Device", &issuer, 365, &san)
                    .expect("should generate device cert");

            let device_cert_path = certs_dir.join("device.pem");
            let device_key_path = certs_dir.join("device-key.pem");
            write_cert(&device_cert_path, &device_cert).expect("should write device cert");
            write_key(&device_key_path, &device_key).expect("should write device key");

            let cfg = Config {
                name: "test-daemon-run".into(),
                runtime_dir: work_dir.join("run"),
                state_dir: work_dir.join("state"),
                cache_dir: work_dir.join("cache"),
                logs_dir: work_dir.join("logs"),
                config_dir: work_dir.join("config"),
                sync: SyncConfig {
                    quic: Toggle::Enabled(QuicSyncConfig {
                        addr: Addr::from((Ipv4Addr::LOCALHOST, 0)),
                        client_addr: None,
                        root_certs_dir,
                        device_cert: device_cert_path,
                        device_key: device_key_path,
                    }),
                },
                #[cfg(feature = "afc")]
                afc: Toggle::Enabled(aranya_daemon::config::AfcConfig {
                    shm_path,
                    max_chans: 100,
                }),
            };

            for dir in [
                &cfg.runtime_dir,
                &cfg.state_dir,
                &cfg.cache_dir,
                &cfg.logs_dir,
                &cfg.config_dir,
            ] {
                rt.block_on(aranya_util::create_dir_all(dir))
                    .expect("should be able to create directory");
            }

            (tmp_dir, rt, cfg)
        })
        .bench_values(|(tmp_dir, rt, cfg)| {
            let daemon = rt
                .block_on(Daemon::load(cfg))
                .expect("We should always be able to construct a daemon");

            (tmp_dir, rt, daemon)
        });
}
