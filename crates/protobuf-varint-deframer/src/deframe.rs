use bytes::{Buf, Bytes, BytesMut};
use getset::{Getters, Setters};
use tap::Pipe as _;
use typed_builder::TypedBuilder;

use crate::error::*;

/// Default maximum legal value, 4 MB, for the payload length in bytes.
pub const DEFAULT_MAX_PAYLOAD_LENGTH: usize = 4 * 0x400 * 0x400;

pub const UNLIMITED_MAX_PAYLOAD_LENGTH: usize = usize::MAX;

/// Maximum legal value and also the default value for the length delimiter.
pub const MAX_LENGTH_DELIMITER: u64 = u64::MAX;

/// Maximum legal value and also the default value
/// for the length delimiter stack length in bytes.
const MAX_DELIMITER_STACK_LENGTH: usize = prost::encoding::encoded_len_varint(MAX_LENGTH_DELIMITER);

#[derive(Debug, Clone, Getters, Setters, TypedBuilder)]
pub struct Deframer {
    /// Maximum legal value for the payload length in bytes.
    ///
    /// Set to [`UNLIMITED_MAX_PAYLOAD_LENGTH`], i.e., `usize::MAX`, to disable the limit.
    #[getset(get = "pub", set = "pub")]
    #[builder(default = DEFAULT_MAX_PAYLOAD_LENGTH)]
    max_payload_length: usize,

    /// Maximum legal value for the length delimiter in bytes.
    ///
    /// Defaults to [`MAX_LENGTH_DELIMITER`], the maximum size of u64,
    /// equals to 2^64-1,
    /// which is the maximum legal value for the length delimiter in protobuf.
    #[builder(default = MAX_LENGTH_DELIMITER)]
    max_length_delimiter: u64,

    #[builder(default, setter(skip))]
    phase: Phase,

    // Cache fields
    #[builder(default = (*max_length_delimiter).pipe(|m|
        if m == MAX_LENGTH_DELIMITER { MAX_DELIMITER_STACK_LENGTH }
        else { prost::encoding::encoded_len_varint(m) }
    ), setter(skip))]
    max_delimiter_stack_length: usize,
}

#[derive(Debug, Clone, Default)]
enum Phase {
    #[default]
    Idle,

    /// Reading the length delimiter, which is a varint-encoded u64.
    ReadingLengthDelimiter {
        n: usize,
        buf: [u8; MAX_DELIMITER_STACK_LENGTH],
    },

    ReadingPayload {
        left: usize,
        frame: BytesMut,
    },
}

impl Deframer {
    /// Feed data, whether containing a complete frame or a fragment of it, to the deframer.
    ///
    /// Return `Ok` of a deframed frame if it has been completely received,
    /// or `Ok(None)` if more data is needed to complete the frame.
    pub fn feed(&mut self, mut data: impl Buf) -> Result<Option<BytesMut>> {
        let mut out = None;
        while data.has_remaining() && out.is_none() {
            match self.phase {
                Phase::Idle => {
                    self.phase = Phase::ReadingLengthDelimiter {
                        n: 0,
                        buf: [0u8; MAX_DELIMITER_STACK_LENGTH],
                    };
                }

                Phase::ReadingLengthDelimiter {
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
                        return Error::LengthDelimiterExceedsProtocolMax {
                            actual: LengthDelimiterExcess::Unknown,
                            max: self.max_length_delimiter,
                        }
                        .pipe(Err);
                    }

                    if (*buf)[*n - 1] <= 0x7f {
                        let mut stack = Bytes::from(buf[..*n].to_vec());
                        let len = prost::decode_length_delimiter(&mut stack)?;
                        {
                            let len = len as u64;
                            let max = self.max_length_delimiter;
                            if len > max {
                                return Error::LengthDelimiterExceedsProtocolMax {
                                    actual: len.into(),
                                    max,
                                }
                                .pipe(Err);
                            }
                        }
                        let max = self.max_payload_length;
                        if len > max {
                            return Error::PayloadLengthTooLarge { actual: len, max }.pipe(Err);
                        }
                        if len == 0 {
                            // Empty payload
                            self.phase = Phase::Idle;
                            out = BytesMut::new().into();
                        } else {
                            self.phase = Phase::ReadingPayload {
                                left: len,
                                frame: BytesMut::with_capacity(len),
                            };
                        }
                    }
                }

                Phase::ReadingPayload {
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
