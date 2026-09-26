use bytes::BytesMut;
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, sleep};

use protobuf_varint_framer::Framer;
use zconned_types::{Handshake, IncomingFrame, OutgoingFrame, PROTOCOL_VERSION};

use crate::ZconnedResult;
use crate::error::ProtocolError;

const ECHO_DELAY: Duration = Duration::from_secs(1);

enum State {
    BeforeHandshake,
    Running,
}

pub async fn run<R, W>(stdin: &mut BufReader<R>, stdout: &mut W) -> ZconnedResult<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut state = State::BeforeHandshake;
    let mut framer = Framer::builder().max_payload_length(usize::MAX).build();

    loop {
        let mut chunk = BytesMut::new();
        if stdin.read_buf(&mut chunk).await? == 0 {
            // EOF
            return framer.is_idle().ok_or(ProtocolError::TruncatedFrame.into());
        }

        let mut view = &chunk[..];
        loop {
            match framer.feed(&mut view).map_err(ProtocolError::from)? {
                None => break,
                Some(payload) => {
                    match state {
                        State::BeforeHandshake => {
                            match Handshake::decode(payload) {
                                Ok(Handshake { version }) => {
                                    if version != PROTOCOL_VERSION {
                                        return Ok(()); // version mismatch: silent close
                                    }
                                    write_frame(
                                        stdout,
                                        Handshake {
                                            version: PROTOCOL_VERSION,
                                        },
                                    )
                                    .await?;
                                    state = State::Running;
                                }
                                Err(_) => return Ok(()), // first frame != handshake: close
                            }
                        }
                        State::Running => {
                            if let Ok(msg) = IncomingFrame::decode(payload) {
                                sleep(ECHO_DELAY).await; // the 1s echo contract
                                write_frame(stdout, OutgoingFrame { text: msg.text }).await?;
                            }
                        }
                    }
                }
            }
        }
    }
}

async fn write_frame<W: AsyncWriteExt + Unpin, M: prost::Message + Unpin>(
    stdout: &mut W,
    msg: M,
) -> ZconnedResult<()> {
    let bytes = msg.encode_length_delimited_to_vec();
    stdout.write_all(&bytes).await?;
    stdout.flush().await?;
    Ok(())
}
