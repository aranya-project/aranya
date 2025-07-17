use bytes::{Bytes, BytesMut};
use s2n_quic::stream;

/// Read all of a stream until it has finished.
///
/// A bit more efficient than going through the `AsyncRead`-based impl,
/// especially if there was only one chunk of data. Also avoids needing to
/// convert/handle an `io::Error`.
pub async fn read_to_end(stream: &mut stream::ReceiveStream) -> Result<Bytes, stream::Error> {
    let Some(first) = stream.receive().await? else {
        return Ok(Bytes::new());
    };
    let Some(mut more) = stream.receive().await? else {
        return Ok(first);
    };
    let mut buf = BytesMut::from(first);
    loop {
        buf.extend_from_slice(&more);
        if let Some(even_more) = stream.receive().await? {
            more = even_more;
        } else {
            break;
        }
    }
    Ok(buf.freeze())
}

/// Indicates whether the stream error is "connection closed without error".
pub fn is_close_error(err: stream::Error) -> bool {
    matches!(
        err,
        stream::Error::ConnectionError {
            error: s2n_quic::connection::Error::Closed { .. },
            ..
        },
    )
}
