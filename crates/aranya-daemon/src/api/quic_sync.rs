use tokio::sync::broadcast;

use super::Msg;

#[derive(Debug)]
/// Held by [`super::DaemonApiServer`] when the QUIC syncer is used
pub(crate) struct Data {
    /// Channel for sending PSK updates
    pub(crate) psk_send: broadcast::Sender<Msg>,

    /// See [`crate::config::QSConfig::service_name`]
    pub(crate) service_name: String,
}
