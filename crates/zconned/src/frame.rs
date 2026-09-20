use bytes::{Buf, Bytes, BytesMut};
use getset::{Getters, Setters};
use tap::Pipe;
use tokio::io::AsyncWriteExt;
use typed_builder::TypedBuilder;

use crate::{ZconnedError, ZconnedResult};

#[derive(Debug, Clone, Getters, Setters, TypedBuilder)]
pub struct Framer {
    #[getset(get = "pub", set = "pub")]
    max_payload_length: usize,

    #[builder(default, setter(skip))]
    phase: Phase,
}

#[derive(Debug, Clone, Default)]
enum Phase {
    #[default]
    Idle,
    Prefix {
        n: u8,
        buf: [u8; 10],
    },
    Body {
        left: usize,
        frame: BytesMut,
    },
}

impl Framer {
    pub fn feed(&mut self, mut data: impl Buf) -> ZconnedResult<Option<BytesMut>> {
        let mut out = None;
        while data.has_remaining() && out.is_none() {
            match self.phase {
                Phase::Idle => {
                    self.phase = Phase::Prefix {
                        n: 0,
                        buf: [0u8; 10],
                    };
                }

                Phase::Prefix {
                    ref mut n,
                    ref mut buf,
                } => {
                    // accumulate <= 10bytes; MSB-set byte = continuation.
                    while *n < 10 && data.has_remaining() {
                        let b = data.get_u8();
                        (*buf)[*n as usize] = b;
                        *n += 1;
                        if b <= 0x7f {
                            break;
                        }
                    }

                    if *n == 10 && (*buf)[9] >= 0x02 {
                        return "Bad delimiter"
                            .to_owned()
                            .pipe(ZconnedError::Protocol)
                            .pipe(Err);
                    }

                    if (*buf)[*n as usize - 1] <= 0x7f {
                        let mut stack = Bytes::from(buf[..*n as usize].to_vec());
                        let len = match prost::decode_length_delimiter(&mut stack) {
                            Ok(len) => len,
                            Err(e) => {
                                return format!("Failed to decode length delimiter: {}", e)
                                    .pipe(ZconnedError::Protocol)
                                    .pipe(Err);
                            }
                        };
                        if len > self.max_payload_length {
                            return format!(
                                "Payload length {} exceeds maximum {}",
                                len, self.max_payload_length
                            )
                            .pipe(ZconnedError::Protocol)
                            .pipe(Err);
                        }
                        self.phase = Phase::Body {
                            left: len,
                            frame: BytesMut::with_capacity(len),
                        };
                    }
                }

                Phase::Body {
                    ref mut left,
                    ref mut frame,
                } => {
                    let take = std::cmp::min(*left, data.remaining());
                    let view = data.chunk();
                    (*frame).extend_from_slice(&view[..take]);
                    data.advance(take);
                    *left -= take;
                    if *left == 0 {
                        let mut done = BytesMut::new();
                        std::mem::swap(&mut done, frame);
                        self.phase = Phase::Idle;
                        out = Some(done);
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn is_idle(&self) -> bool {
        matches!(self.phase, Phase::Idle)
    }
}

pub async fn write_frame<W: AsyncWriteExt + Unpin, M: prost::Message + Unpin>(
    stdout: &mut W,
    msg: M,
) -> ZconnedResult<()> {
    let bytes = msg.encode_length_delimited_to_vec();
    stdout.write_all(&bytes).await?;
    stdout.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use pretty_assertions::assert_eq;
    use prost::Message;

    use zconned_types::IncomingFrame;

    fn feed_all(f: &mut Framer, chunk: &[u8]) -> ZconnedResult<Vec<(usize, BytesMut)>> {
        let mut out = Vec::new();
        let mut view = chunk;
        loop {
            match f.feed(&mut view) {
                Ok(Some(frame)) => out.push((frame.len(), frame)),
                Ok(None) => return Ok(out),
                Err(e) => return Err(e),
            }
            if view.is_empty() {
                return Ok(out);
            }
        }
    }

    #[test]
    fn one_complete_frame() {
        let bytes = IncomingFrame { text: "hi".into() }.encode_length_delimited_to_vec();
        let mut f = Framer::builder().max_payload_length(1024).build();
        let frames = feed_all(&mut f, &bytes).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(
            &frames[0].1[..],
            &IncomingFrame { text: "hi".into() }.encode_to_vec()
        );
    }

    #[test]
    fn byte_by_byte_chunks_degrades_uniformly() {
        let bytes = IncomingFrame {
            text: "hello".into(),
        }
        .encode_length_delimited_to_vec();
        let mut f = Framer::builder().max_payload_length(1024).build();
        let mut frames: Vec<BytesMut> = Vec::new();
        for b in bytes {
            let view: &[u8] = &[b];
            match f.feed(view) {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => (),
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn oversized_payload_rejected_before_allocation() {
        // varint for 128: 0x80 0x01
        let mut bytes = vec![0x80, 0x01];
        bytes.extend(std::iter::repeat_n(0u8, 128));
        let mut f = Framer::builder().max_payload_length(64).build();
        assert!(feed_all(&mut f, &bytes).is_err());
    }

    #[test]
    fn corrupt_delimiter_rejected() {
        let bytes = [0x80u8; 10];
        let mut f = Framer::builder().max_payload_length(1024).build();
        assert!(feed_all(&mut f, &bytes).is_err());
    }

    #[test]
    fn empty_chunk_is_noop() {
        let mut f = Framer::builder().max_payload_length(1024).build();
        assert_eq!(f.feed(&[] as &[u8]).unwrap(), None);
    }
}
