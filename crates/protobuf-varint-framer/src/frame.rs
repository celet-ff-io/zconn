use bytes::{Buf, Bytes, BytesMut};
use getset::{Getters, Setters};
use tap::Pipe;
use typed_builder::TypedBuilder;

use crate::error::*;

/// Maximum legal value and also the default value for the length delimiter.
const MAX_DELIMITER: u64 = u64::MAX;

/// Maximum legal value and also the default value
/// for the length delimiter stack length in bytes.
const MAX_DELIMITER_STACK_LENGTH: usize = prost::encoding::encoded_len_varint(MAX_DELIMITER);

#[derive(Debug, Clone, Getters, Setters, TypedBuilder)]
pub struct Framer {
    #[getset(get = "pub", set = "pub")]
    max_payload_length: usize,

    #[builder(default = MAX_DELIMITER)]
    max_delimiter: u64,

    #[builder(default, setter(skip))]
    phase: Phase,

    // Cache fields
    #[builder(default = (*max_delimiter).pipe(|m|
        if m == MAX_DELIMITER { MAX_DELIMITER_STACK_LENGTH }
        else { prost::encoding::encoded_len_varint(m) }
    ))]
    max_delimiter_stack_length: usize,
}

#[derive(Debug, Clone, Default)]
enum Phase {
    #[default]
    Idle,
    LengthDelimiter {
        n: usize,
        buf: [u8; MAX_DELIMITER_STACK_LENGTH],
    },
    Payload {
        left: usize,
        frame: BytesMut,
    },
}

impl Framer {
    pub fn feed(&mut self, mut data: impl Buf) -> FrameResult<Option<BytesMut>> {
        let mut out = None;
        while data.has_remaining() && out.is_none() {
            match self.phase {
                Phase::Idle => {
                    self.phase = Phase::LengthDelimiter {
                        n: 0,
                        buf: [0u8; MAX_DELIMITER_STACK_LENGTH],
                    };
                }

                Phase::LengthDelimiter {
                    ref mut n,
                    ref mut buf,
                } => {
                    // accumulate <= MAX_DELIMITER_STACK_LENGTH bytes; MSB-set byte = continuation.
                    let max_delimiter_stack_length = self.max_delimiter_stack_length;
                    while *n < max_delimiter_stack_length && data.has_remaining() {
                        let b = data.get_u8();
                        (*buf)[*n] = b;
                        *n += 1;
                        if b <= 0x7f {
                            break;
                        }
                    }

                    if *n >= max_delimiter_stack_length && (*buf)[*n - 1] & 0x80 != 0 {
                        return FrameError::LengthDelimiterExceedsProtocolMax {
                            actual: LengthDelimiterExcess::Unknown,
                            max: self.max_delimiter,
                        }
                        .pipe(Err);
                    }

                    if (*buf)[*n - 1] <= 0x7f {
                        let mut stack = Bytes::from(buf[..*n].to_vec());
                        let len = prost::decode_length_delimiter(&mut stack)?;
                        {
                            let len = len as u64;
                            let max = self.max_delimiter;
                            if len > max {
                                return FrameError::LengthDelimiterExceedsProtocolMax {
                                    actual: len.into(),
                                    max,
                                }
                                .pipe(Err);
                            }
                        }
                        let max = self.max_payload_length;
                        if len > max {
                            return FrameError::PayloadLengthTooLarge { actual: len, max }
                                .pipe(Err);
                        }
                        self.phase = Phase::Payload {
                            left: len,
                            frame: BytesMut::with_capacity(len),
                        };
                    }
                }

                Phase::Payload {
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

#[cfg(test)]
mod tests {
    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn one_complete_frame() {
        let payload = [0x0a, 0x02, 0x68, 0x69]; // arbitrary bytes ("hi" as a proto string field)
        let bytes = frame(&payload);
        let mut f = Framer::builder().max_payload_length(1024).build();
        let frames = feed_all(&mut f, &bytes).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(&frames[0].1[..], &payload[..]);
    }

    #[test]
    fn byte_by_byte_chunks_degrades_uniformly() {
        let payload = b"hello";
        let bytes = frame(payload);
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
        assert_eq!(&frames[0][..], &payload[..]);
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

    #[test]
    fn oversized_length_is_also_prost_overflow() {
        static BYTES: [u8; 10] = [0x80u8; 10];
        let mut f = Framer::builder().max_payload_length(1024).build();
        assert!(feed_all(&mut f, &BYTES).is_err());

        let mut buf = Bytes::from(&BYTES[..]);
        assert!(prost::encoding::decode_length_delimiter(&mut buf).is_err());
    }

    fn len_prefix(n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut v = n as u64;
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
        out
    }

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut f = len_prefix(payload.len());
        f.extend_from_slice(payload);
        f
    }

    fn feed_all(f: &mut Framer, chunk: &[u8]) -> FrameResult<Vec<(usize, BytesMut)>> {
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
}
