use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

use crate::error::CodecError;
use zconned_crypto::peer;

/// The JSON view of an identity's public keys: base64 key strings
/// (project bytes-in-JSON convention). Serialize it with serde_json
/// directly; parse back with `serde_json::from_str` + `try_into`.
///
/// @see [`peer::MailboxPublicSet`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxPublicSetJson {
    /// Signing public key, standard base64.
    pub sign: String,
    /// Static DH public key, standard base64.
    pub static_dh: String,
}

impl From<peer::MailboxPublicSet> for MailboxPublicSetJson {
    fn from(keys: peer::MailboxPublicSet) -> Self {
        Self {
            sign: B64.encode(keys.sign()),
            static_dh: B64.encode(keys.static_dh()),
        }
    }
}

impl TryFrom<MailboxPublicSetJson> for peer::MailboxPublicSet {
    type Error = CodecError;

    /// # Errors
    /// [`CodecError::Field`] on wrong key length;
    /// [`CodecError::Base64`] on malformed base64.
    fn try_from(dto: MailboxPublicSetJson) -> Result<Self, Self::Error> {
        Ok(peer::MailboxPublicSet::builder()
            .sign(decode_key::<{ peer::SIGN_PUB_LEN }>("sign", &dto.sign)?)
            .static_dh(decode_key::<{ peer::STATIC_DH_PUB_LEN }>(
                "static_dh",
                &dto.static_dh,
            )?)
            .build())
    }
}

fn decode_key<const N: usize>(field: &'static str, raw: &str) -> Result<[u8; N], CodecError> {
    let decoded = B64.decode(raw)?;
    let found = decoded.len();
    let bytes: [u8; N] = decoded.try_into().map_err(|_: Vec<u8>| CodecError::Field {
        field,
        expected: N,
        found,
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn sample_set() -> peer::MailboxPublicSet {
        peer::MailboxPublicSet::builder()
            .sign([1u8; 32])
            .static_dh([2u8; 32])
            .build()
    }

    fn sample_json() -> String {
        serde_json::to_string(&MailboxPublicSetJson::from(sample_set())).expect("to_json")
    }

    #[test]
    fn json_roundtrip_preserves_public_key_set() {
        let back: peer::MailboxPublicSet =
            serde_json::from_str::<MailboxPublicSetJson>(&sample_json())
                .expect("from_str")
                .try_into()
                .expect("try_into");
        let expected = peer::MailboxPublicSet::builder()
            .sign([1u8; 32])
            .static_dh([2u8; 32])
            .build();
        assert_eq!(back, expected);
    }

    #[test]
    fn json_shape_is_flat_keys() {
        let value: serde_json::Value = serde_json::from_str(&sample_json()).expect("value");
        assert!(value["sign"].is_string());
        assert!(value["static_dh"].is_string());
        assert_eq!(value.as_object().expect("object").len(), 2);
    }

    #[test]
    fn wrong_length_key_errors() {
        let dto = MailboxPublicSetJson::from(
            peer::MailboxPublicSet::builder()
                .sign([0u8; 32])
                .static_dh([0u8; 32])
                .build(),
        );
        let mut dto = dto;
        dto.sign = B64.encode([0u8; 3]);
        let json = serde_json::to_string(&dto).expect("json");
        let dto: MailboxPublicSetJson = serde_json::from_str(&json).expect("from_str");
        match peer::MailboxPublicSet::try_from(dto) {
            Err(CodecError::Field {
                field: "sign",
                expected: peer::SIGN_PUB_LEN,
                found: 3,
            }) => {}
            other => panic!("expected Field error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_base64_errors() {
        let mut dto = MailboxPublicSetJson::from(
            peer::MailboxPublicSet::builder()
                .sign([0u8; 32])
                .static_dh([0u8; 32])
                .build(),
        );
        dto.sign = "!!!not base64!!!".to_owned();
        assert!(matches!(
            peer::MailboxPublicSet::try_from(dto),
            Err(CodecError::Base64(_))
        ));
    }

    #[test]
    fn inverse_pair_is_static_dh() {
        let keys = peer::MailboxPublicSet::builder()
            .sign([7u8; 32])
            .static_dh([9u8; 32])
            .build();
        let json =
            serde_json::to_string(&MailboxPublicSetJson::from(keys.clone())).expect("to_json");
        let back: peer::MailboxPublicSet = serde_json::from_str::<MailboxPublicSetJson>(&json)
            .expect("from_str")
            .try_into()
            .expect("try_into");
        assert_eq!(back, keys);
    }
}
