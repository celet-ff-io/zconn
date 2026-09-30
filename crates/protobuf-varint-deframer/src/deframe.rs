use bytes::{Buf, Bytes, BytesMut};
use getset::{Getters, Setters};
use tap::Pipe;
use typed_builder::TypedBuilder;

use crate::error::*;

/// Default maximum legal value, 4 MB, for the payload length in bytes.
const DEFAULT_MAX_PAYLOAD_LENGTH: usize = 4 * 0x400 * 0x400;

/// Maximum legal value and also the default value for the length delimiter.
const MAX_DELIMITER: u64 = u64::MAX;

/// Maximum legal value and also the default value
/// for the length delimiter stack length in bytes.
const MAX_DELIMITER_STACK_LENGTH: usize = prost::encoding::encoded_len_varint(MAX_DELIMITER);

#[derive(Debug, Clone, Getters, Setters, TypedBuilder)]
pub struct Framer {
    #[getset(get = "pub", set = "pub")]
    #[builder(default = DEFAULT_MAX_PAYLOAD_LENGTH)]
    max_payload_length: usize,

    #[builder(default = MAX_DELIMITER)]
    max_delimiter: u64,

    #[builder(default, setter(skip))]
    phase: Phase,

    // Cache fields
    #[builder(default = (*max_delimiter).pipe(|m|
        if m == MAX_DELIMITER { MAX_DELIMITER_STACK_LENGTH }
        else { prost::encoding::encoded_len_varint(m) }
    ), setter(skip))]
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
                    // Accumulate <= MAX_DELIMITER_STACK_LENGTH bytes; MSB-set byte = continuation.
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
                        if len == 0 {
                            // Empty payload
                            self.phase = Phase::Idle;
                            out = BytesMut::new().into();
                        } else {
                            self.phase = Phase::Payload {
                                left: len,
                                frame: BytesMut::with_capacity(len),
                            };
                        }
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

    // ---- basic behavior --------------------------------------------------

    #[test]
    fn one_complete_frame() {
        let payload = [0x0a, 0x02, 0x68, 0x69];
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
    fn empty_chunk_is_noop() {
        let mut f = Framer::builder().max_payload_length(1024).build();
        assert_eq!(f.feed(&[] as &[u8]).unwrap(), None);
    }

    // ---- rejection paths ------------------------------------------------

    #[test]
    fn oversized_payload_rejected_before_allocation() {
        // varint for 128: 0x80 0x01; escapes the prefix stage, must be
        // rejected at the payload cap BEFORE with_capacity.
        let mut bytes = vec![0x80, 0x01];
        bytes.extend(std::iter::repeat_n(0u8, 128));
        let mut f = Framer::builder().max_payload_length(64).build();
        assert!(matches!(
            feed_all(&mut f, &bytes),
            Err(FrameError::PayloadLengthTooLarge {
                actual: 128,
                max: 64
            })
        ));
    }

    #[test]
    fn corrupt_delimiter_rejected() {
        // 10x0x80: stack fills, last byte still has continuation bit.
        let bytes = [0x80u8; 10];
        let mut f = Framer::builder().max_payload_length(1024).build();
        assert!(matches!(
            feed_all(&mut f, &bytes),
            Err(FrameError::LengthDelimiterExceedsProtocolMax { .. })
        ));
    }

    #[test]
    fn huge_declared_rejected_at_stack_before_allocation() {
        // max_delimiter=1024  ->  stack = encoded_len_varint(1024) = 2.
        // 131072 encodes in 3 bytes; the 2nd byte still has the
        // continuation bit -> rejected at the stack, never decoded/allc'd.
        let mut bytes = len_delimiter(131072);
        bytes.push(0); // payload not reached anyway
        let mut f = Framer::builder()
            .max_payload_length(1024)
            .max_delimiter(1024)
            .build();
        assert!(matches!(
            feed_all(&mut f, &bytes),
            Err(FrameError::LengthDelimiterExceedsProtocolMax { .. })
        ));
    }

    #[test]
    fn huge_declared_rejected_at_payload_cap_without_allocation() {
        // Default max_delimiter=u64::MAX (protobuf mode, stack 10):
        // a full-width prefix decodes fine, then the payload cap rejects
        // BEFORE with_capacity — no allocation for a u64::MAX claim.
        let mut bytes = len_delimiter(u64::MAX as usize);
        bytes.push(0);
        let mut f = Framer::builder().max_payload_length(1024).build();
        assert!(matches!(
            feed_all(&mut f, &bytes),
            Err(FrameError::PayloadLengthTooLarge { .. })
        ));
    }

    #[test]
    fn max_delimiter_acts_as_value_cap() {
        let mut f = Framer::builder()
            .max_payload_length(4096)
            .max_delimiter(1024)
            .build();
        // 1024 is exactly at the delimiter cap: legal.
        let n_ok = frame(&vec![0xabu8; 1024]);
        feed_all(&mut f, &n_ok).unwrap();

        // 1025 is one past: rejected with the value-excess error.
        let bytes = frame(&[0xabu8; 1025]); // 3 bytes: [0x80,0x08,0x01]... 2-byte 0x81 0x08
        assert!(matches!(
            feed_all(&mut f, &bytes),
            Err(FrameError::LengthDelimiterExceedsProtocolMax { .. })
        ));
    }

    // ---- prost oracle (semantics: prefix == prost, byte for byte) -------

    #[test]
    fn frame_lengths_match_prost_oracle() {
        // Payloads that can actually be filled; the big ones are exercised
        // only on the rejection paths above.
        let cases = [0, 1, 127, 128, 16383, 16384];
        for n in cases {
            let payload = vec![0xabu8; n];
            let mut bytes = len_delimiter(n);
            bytes.extend_from_slice(&payload);

            let mut f = Framer::builder()
                .max_payload_length(16 * 1024 * 1024)
                .build();
            let frames = feed_all(&mut f, &bytes).unwrap();
            assert_eq!(frames.len(), 1, "n={n}");
            assert_eq!(&frames[0].1[..], &payload[..], "n={n}");

            let mut encoded = Vec::with_capacity(16);
            prost::encoding::encode_length_delimiter(n, &mut encoded).unwrap();
            assert_eq!(encoded, len_delimiter(n), "prefix mismatch at n={n}");
        }
    }

    #[test]
    fn oversized_length_is_also_prost_overflow() {
        static BYTES: [u8; 10] = [0x80u8; 10];
        let mut f = Framer::builder().max_payload_length(1024).build();
        assert!(feed_all(&mut f, &BYTES).is_err());

        let mut buf = Bytes::from(&BYTES[..]);
        assert!(prost::encoding::decode_length_delimiter(&mut buf).is_err());
    }

    #[test]
    fn u64_max_prefix_is_a_valid_varint() {
        // Wire-level truth, independent of the framer (so a framer built
        // with a small max_delimiter can reject it early instead).
        let mut buf = Bytes::from(len_delimiter(u64::MAX as usize));
        assert_eq!(
            prost::encoding::decode_length_delimiter(&mut buf).unwrap(),
            u64::MAX as usize
        );
    }

    #[test]
    fn zero_length_frame_completes_instantly_and_idles() {
        let mut f = Framer::builder().max_payload_length(1024).build();
        let frames = feed_all(&mut f, &[0x00]).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].1.len(), 0); // empty payload
        assert!(f.is_idle(), "must be Idle after a zero-length frame");
    }

    // ---- helpers

    /// LEB128 length delimiter
    fn len_delimiter(n: usize) -> Vec<u8> {
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
        let mut f = len_delimiter(payload.len());
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
