use serde::{Deserialize, Serialize};

/// One transcript.jsonl row: the at-rest record of one message —
/// the anchor Msg's projection in hex digests.
// Self-verifying: the meta digest = H(canonical anchor Msg),
// rebuildable from the row alone. Different medium than the wire:
// hex, not base64.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    /// Observer-side annotations.
    pub meta: RowMeta,
    /// The message's anchor projection.
    pub msg: RowMsg,
}

/// The observer-facts half of a [`Row`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowMeta {
    /// Local record time, RFC 3339.
    pub ts: String,
    /// Digest algorithm name; the name implies the output length.
    pub algo: String,
    /// Lowercase hex digest of the message's canonical bytes.
    pub digest: String,
}

/// The anchor projection of a [`zconned_material::Msg`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowMsg {
    /// Material era (this row's fsck handles era 1).
    pub ver_major: u32,
    /// Omitted when 0, mirroring the wire omission rule.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ver_minor: u32,
    /// Chain parents (hex digests). Missing key = none.
    #[serde(default)]
    pub prev: Vec<RowMsgRef>,
    /// The content address (kindless: the kind lives inside the
    /// addressed resource).
    pub content: RowResourceRef,
    /// Claim entries, order-free, keyed by kind.
    #[serde(default)]
    pub claims: Vec<RowClaim>,
}

/// A chain-parent anchor (hex-digest form of a material MsgRef).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowMsgRef {
    pub ver_major: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ver_minor: u32,
    pub algo: String,
    /// Lowercase hex.
    pub digest: String,
}

/// A content address (hex form of a material ResourceRef).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowResourceRef {
    pub algo: String,
    /// Lowercase hex digest of H(canonical Value{kind, data}).
    pub digest: String,
}

/// One resources.jsonl row: one addressed kinded value.
/// Digest = H(canonical Value{kind, data}).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRow {
    /// Digest algorithm name.
    pub algo: String,
    /// Lowercase hex digest of H(canonical Value{kind, data}).
    pub digest: String,
    /// The kind (readable projection of the addressed pair).
    pub kind: String,
    /// The value bytes, base64.
    pub data: String,
}

/// A claim entry (hex form of a material Claim).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RowClaim {
    pub kind: String,
    /// Hex form of the claim's ResourceRef.
    #[serde(rename = "ref")]
    pub ref_: RowResourceRef,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}
