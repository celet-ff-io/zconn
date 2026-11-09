//! The thread-file store: one directory per thread —
//! `<root>/threads/<thread-id>/{transcript.jsonl, resources.jsonl}`.
//!
//! A thread's id = the parent ref its earliest message chains from;
//! it doubles as the directory name (`{algo}-{hexdigest}`).
//!
//! Commit order: resource rows first, then the transcript row.
//! Append-only; values are raw bytes.

use std::collections::HashMap;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use crate::render::render_row;
use zconned_codec::ResourceRow;
use zconned_codec::Row;
use zconned_crypto::DIGEST_ALGO;
use zconned_material::{Msg, Resource, Value};

use crate::error::{Error, Result};

/// Hex (lowercase) -> bytes.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b: u8| b.is_ascii_hexdigit()) {
        return Err(Error::DigestNotation {
            expected: "hex digits",
            found: hex.to_owned(),
        });
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| Error::DigestNotation {
                expected: "hex digits",
                found: hex.to_owned(),
            })
        })
        .collect()
}

/// base64 (standard) -> bytes.
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| Error::DigestNotation {
            expected: "base64",
            found: s.to_owned(),
        })
}

/// The plaintext values behind a commit's anchors.
// Cross-checked against the anchors before anything is written.
#[derive(Debug, Clone)]
pub struct CommitValues {
    pub content: Value,
    pub claims: Vec<Value>,
}

/// The per-thread file store.
pub struct Store {
    threads_dir: PathBuf,
}

/// A thread id: the parent ref the thread's earliest message chains
/// from. Carried as binary; rendered as `{algo}-{hexdigest}` only
/// for the directory name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThreadId {
    pub algo: String,
    pub digest: Vec<u8>,
}

impl ThreadId {
    /// Parse a file stem back into a thread id (`algo-hex`).
    pub fn from_stem(stem: &str) -> Option<ThreadId> {
        // The algo name may itself contain dashes ("sha3-256"); the
        // digest hex never does — split at the LAST dash.
        let (algo, digest_hex) = stem.rsplit_once('-')?;
        Some(ThreadId {
            algo: algo.to_owned(),
            digest: crate::store::hex_to_bytes(digest_hex).ok()?,
        })
    }

    /// The directory name of this thread.
    pub fn stem(&self) -> String {
        format!("{}-{}", self.algo, to_lower_hex(&self.digest))
    }

    /// The thread id as a material MsgRef.
    pub fn to_ref(&self) -> Result<zconned_material::MsgRef> {
        Ok(zconned_material::MsgRef {
            ver_major: 1,
            ver_minor: 0,
            algo: self.algo.clone(),
            digest: self.digest.clone(),
        })
    }

    /// The thread id from a ref.
    pub fn from_ref(r: &zconned_material::MsgRef) -> ThreadId {
        ThreadId {
            algo: r.algo.clone(),
            digest: r.digest.clone(),
        }
    }
}

impl Store {
    /// Open (and create) the store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> io::Result<Store> {
        let threads_dir = root.as_ref().join("threads");
        std::fs::create_dir_all(&threads_dir)?;
        Ok(Store { threads_dir })
    }

    /// Enumerate threads: every thread directory = one thread.
    pub fn threads(&self) -> io::Result<Vec<ThreadId>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.threads_dir)? {
            let path = entry?.path();
            if !path.is_dir() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if let Some(id) = ThreadId::from_stem(name) {
                out.push(id);
            }
        }
        out.sort_by_key(|a| a.stem());
        Ok(out)
    }

    /// Commit one message: write the resource rows, then the
    /// transcript row. Returns the rendered row and the resolved
    /// values. `values` must match `msg`'s anchors.
    pub fn commit(
        &self,
        transport_bytes: &[u8],
        msg: &Msg,
        values: &CommitValues,
        thread: &ThreadId,
        recorded_at: String,
    ) -> Result<(Row, Vec<Resource>)> {
        let row = render_row(transport_bytes, recorded_at)?;
        // The core validates what it writes.
        crate::fsck_row(&row)?;

        // The caller's values must match the record's addresses.
        let content_anchor = msg
            .content
            .as_ref()
            .ok_or(crate::store::Error::MissingContent)?;
        Self::check_binding(
            &content_anchor.algo,
            &content_anchor.digest,
            &values.content,
        )?;
        if values.claims.len() != msg.claims.len() {
            return Err(Error::AnchorBinding {
                why: "claims count mismatch between anchors and values".to_owned(),
            });
        }
        for (anchor, value) in msg.claims.iter().zip(values.claims.iter()) {
            if anchor.kind != value.kind {
                return Err(Error::AnchorBinding {
                    why: format!(
                        "claim kind mismatch: anchor {:?} vs value {:?}",
                        anchor.kind, value.kind
                    ),
                });
            }
            let claim_ref = anchor.r#ref.as_ref().ok_or_else(|| Error::AnchorBinding {
                why: format!("claim {:?} carries no ref", anchor.kind),
            })?;
            Self::check_binding(&claim_ref.algo, &claim_ref.digest, value)?;
        }

        // Resources first; dedup by digest.
        let mut existing = self.resources(thread)?;
        let mut rows: Vec<ResourceRow> = Vec::new();
        let mut resolved: Vec<Resource> = Vec::new();
        for value in std::iter::once(&values.content).chain(values.claims.iter()) {
            let digest = zconned_material::resource_digest(&value.kind, &value.data);
            let digest_hex = to_lower_hex(&digest);
            if value.data.is_empty() {
                // An empty value occupies no resource row; its
                // anchor still pins the digest of the empty pair.
                continue;
            }
            resolved.push(Resource {
                algo: DIGEST_ALGO.to_owned(),
                digest: digest.to_vec(),
                kind: value.kind.clone(),
                data: value.data.clone(),
            });
            if existing.iter().any(|r| r.digest == digest_hex)
                || rows.iter().any(|r| r.digest == digest_hex)
            {
                continue;
            }
            rows.push(ResourceRow {
                algo: DIGEST_ALGO.to_owned(),
                digest: digest_hex,
                kind: value.kind.clone(),
                data: base64_encode(&value.data),
            });
        }
        if !rows.is_empty() {
            std::fs::create_dir_all(self.thread_dir(thread))?;
            append_jsonl(&self.resources_path(thread), &rows)?;
            existing.extend(rows);
        }

        // Then the transcript row.
        std::fs::create_dir_all(self.thread_dir(thread))?;
        let line = serde_json::to_string(&row)?;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.transcript_path(thread))?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
        Ok((row, resolved))
    }

    /// The binding check: H(canonical Value) == digest.
    fn check_binding(algo: &str, digest: &[u8], value: &Value) -> Result<()> {
        if algo != DIGEST_ALGO {
            return Err(Error::AnchorBinding {
                why: format!("unknown digest algo {algo:?}"),
            });
        }
        let want = zconned_material::resource_digest(&value.kind, &value.data);
        if want.as_slice() != digest {
            return Err(Error::AnchorBinding {
                why: format!(
                    "digest mismatch for kind {:?}: the anchor does not address this value",
                    value.kind
                ),
            });
        }
        Ok(())
    }

    /// A thread's transcript rows (file order = commit order).
    pub fn thread_rows(&self, thread: &ThreadId) -> Result<Vec<Row>> {
        let path = self.transcript_path(thread);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in bytes.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            out.push(serde_json::from_slice(line)?);
        }
        Ok(out)
    }

    /// A thread's resource rows.
    pub fn resources(&self, thread: &ThreadId) -> Result<Vec<ResourceRow>> {
        let path = self.resources_path(thread);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for line in bytes.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }
            out.push(serde_json::from_slice(line)?);
        }
        Ok(out)
    }

    /// Point lookup of one resource by its binary digest. Content
    /// addressing makes duplicates identical, so the first match is
    /// THE resource.
    pub fn find_resource(&self, digest: &[u8]) -> Result<Option<ResourceRow>> {
        let hex = to_lower_hex(digest);
        for thread in self.threads()? {
            for row in self.resources(&thread)? {
                if row.digest == hex {
                    return Ok(Some(row));
                }
            }
        }
        Ok(None)
    }

    /// Every row's message digest -> its thread; keyed by binary
    /// digest; built by a full scan.
    pub fn digest_index(&self) -> Result<HashMap<Vec<u8>, ThreadId>> {
        let mut map = HashMap::new();
        for thread in self.threads()? {
            for row in self.thread_rows(&thread)? {
                let digest = crate::store::hex_to_bytes(&row.meta.digest)?;
                map.insert(digest, thread.clone());
            }
        }
        Ok(map)
    }

    fn thread_dir(&self, thread: &ThreadId) -> PathBuf {
        self.threads_dir.join(thread.stem())
    }

    fn resources_path(&self, thread: &ThreadId) -> PathBuf {
        self.thread_dir(thread).join("resources.jsonl")
    }

    fn transcript_path(&self, thread: &ThreadId) -> PathBuf {
        self.thread_dir(thread).join("transcript.jsonl")
    }
}

fn append_jsonl(path: &Path, rows: &[ResourceRow]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    for row in rows {
        let line = serde_json::to_string(row)?;
        f.write_all(line.as_bytes())?;
        f.write_all(b"\n")?;
    }
    Ok(())
}

pub(crate) fn to_lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
    }
    s
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::base64_decode;
    use prost::Message as _;
    use zconned_material::{Claim, MsgRef, ResourceRef};

    fn genesis_thread(seed: u8) -> ThreadId {
        ThreadId {
            algo: "sha3-256".to_owned(),
            digest: vec![seed; 32],
        }
    }

    fn sample_msg(prev: Vec<MsgRef>, text: &str) -> Msg {
        Msg {
            ver_major: 1,
            ver_minor: 0,
            prev,
            content: Some(ResourceRef {
                algo: "sha3-256".to_owned(),
                digest: zconned_material::resource_digest("text/plain", text.as_bytes()).to_vec(),
            }),
            claims: vec![Claim {
                kind: "application/vnd.zconn.ts".to_owned(),
                r#ref: Some(ResourceRef {
                    algo: "sha3-256".to_owned(),
                    digest: zconned_material::resource_digest(
                        "application/vnd.zconn.ts",
                        b"2026-11-05T12:00:00Z",
                    )
                    .to_vec(),
                }),
            }],
        }
    }

    fn sample_values(text: &str) -> CommitValues {
        CommitValues {
            content: Value {
                kind: "text/plain".to_owned(),
                data: text.as_bytes().to_vec(),
            },
            claims: vec![Value {
                kind: "application/vnd.zconn.ts".to_owned(),
                data: b"2026-11-05T12:00:00Z".to_vec(),
            }],
        }
    }

    fn store() -> Store {
        let dir = std::env::temp_dir().join(format!(
            "zconned-store-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Store::open(dir).unwrap()
    }

    #[test]
    fn commit_writes_resources_before_the_row() {
        let store = store();
        let thread = genesis_thread(0xaa);
        let msg = sample_msg(vec![], "hello");
        let (row, resolved) = store
            .commit(
                &msg.encode_to_vec(),
                &msg,
                &sample_values("hello"),
                &thread,
                "2026-11-05T12:00:00Z".to_owned(),
            )
            .unwrap();

        // Both files exist; the resource row carries the value.
        let resources = store.resources(&thread).unwrap();
        assert_eq!(resources.len(), 2); // content + ts claim
        assert!(resources.iter().any(|r| {
            r.digest == row.msg.content.digest && base64_decode(&r.data).unwrap() == b"hello"
        }));
        assert_eq!(store.thread_rows(&thread).unwrap().len(), 1);
        assert_eq!(store.thread_rows(&thread).unwrap()[0], row);
        // The sidecar payload = the resolved resources.
        assert_eq!(resolved.len(), 2);
        assert!(
            resolved
                .iter()
                .any(|r| r.kind == "text/plain" && r.data == b"hello")
        );
    }

    #[test]
    fn commit_dedups_recurring_values() {
        let store = store();
        let thread = genesis_thread(0xbb);
        let a = sample_msg(vec![], "first");
        let b = sample_msg(vec![], "second");
        store
            .commit(
                &a.encode_to_vec(),
                &a,
                &sample_values("first"),
                &thread,
                "t1".to_owned(),
            )
            .unwrap();
        store
            .commit(
                &b.encode_to_vec(),
                &b,
                &sample_values("second"),
                &thread,
                "t2".to_owned(),
            )
            .unwrap();
        let resources = store.resources(&thread).unwrap();
        // Two contents + ONE ts value (deduped by the kinded digest).
        let ts_rows: Vec<_> = resources
            .iter()
            .filter(|r| r.kind == "application/vnd.zconn.ts")
            .collect();
        assert_eq!(ts_rows.len(), 1);
    }

    #[test]
    fn same_bytes_different_kinds_address_differently() {
        // The kind is IN the digest: two kinded pairs never share an
        // address.
        let store = store();
        let thread = genesis_thread(0xee);
        let mut a = sample_msg(vec![], "hello");
        a.claims.clear();
        let mut b = sample_msg(vec![], "hello");
        b.claims.clear();
        // The markdown message's anchor must address the markdown
        // pair (the kind is IN the digest).
        b.content = Some(ResourceRef {
            algo: "sha3-256".to_owned(),
            digest: zconned_material::resource_digest("text/markdown", b"hello").to_vec(),
        });
        let values_a = CommitValues {
            content: Value {
                kind: "text/plain".to_owned(),
                data: b"hello".to_vec(),
            },
            claims: vec![],
        };
        let values_b = CommitValues {
            content: Value {
                kind: "text/markdown".to_owned(),
                data: b"hello".to_vec(),
            },
            claims: vec![],
        };
        store
            .commit(&a.encode_to_vec(), &a, &values_a, &thread, "t1".to_owned())
            .unwrap();
        store
            .commit(&b.encode_to_vec(), &b, &values_b, &thread, "t2".to_owned())
            .unwrap();
        let resources = store.resources(&thread).unwrap();
        assert_eq!(resources.len(), 2, "two kinded pairs, two rows");
        assert_eq!(resources[0].kind, "text/plain");
        assert_eq!(resources[1].kind, "text/markdown");
    }

    #[test]
    fn empty_values_take_no_resource_row() {
        let store = store();
        let thread = genesis_thread(0xcc);
        let msg = Msg {
            ver_major: 1,
            ver_minor: 0,
            prev: vec![],
            content: Some(ResourceRef {
                algo: "sha3-256".to_owned(),
                digest: zconned_material::resource_digest("text/plain", b"").to_vec(),
            }),
            claims: vec![],
        };
        let values = CommitValues {
            content: Value {
                kind: "text/plain".to_owned(),
                data: Vec::new(),
            },
            claims: vec![],
        };
        store
            .commit(&msg.encode_to_vec(), &msg, &values, &thread, "t".to_owned())
            .unwrap();
        assert!(store.resources(&thread).unwrap().is_empty());
        assert_eq!(store.thread_rows(&thread).unwrap().len(), 1);
    }

    #[test]
    fn binary_values_are_first_class() {
        // Data has two forms: raw bytes (stored — the digest
        // addresses them) and the structured view (the interface
        // layer's derivation). Bytes are bytes — no UTF-8
        // restriction, no notation stage.
        let store = store();
        let thread = genesis_thread(0xdd);
        let data: Vec<u8> = vec![0x00, 0xff, 0xfe, 0x0a];
        let msg = Msg {
            ver_major: 1,
            ver_minor: 0,
            prev: vec![],
            content: Some(ResourceRef {
                algo: "sha3-256".to_owned(),
                digest: zconned_material::resource_digest("application/octet-stream", &data)
                    .to_vec(),
            }),
            claims: vec![],
        };
        let values = CommitValues {
            content: Value {
                kind: "application/octet-stream".to_owned(),
                data: data.clone(),
            },
            claims: vec![],
        };
        let (_, resolved) = store
            .commit(&msg.encode_to_vec(), &msg, &values, &thread, "t".to_owned())
            .unwrap();
        // The row holds the bytes under the mechanical projection;
        // resolving returns the original bytes.
        let stored = store.resources(&thread).unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(base64_decode(&stored[0].data).unwrap(), data);
        assert_eq!(resolved[0].data, data);
    }

    #[test]
    fn a_lying_anchor_is_rejected_before_anything_is_written() {
        // The binding check: the anchors must address the values.
        let store = store();
        let thread = genesis_thread(0xdf);
        let msg = sample_msg(vec![], "hello");
        let values = CommitValues {
            content: Value {
                kind: "text/plain".to_owned(),
                data: b"OTHER".to_vec(),
            },
            claims: sample_values("hello").claims,
        };
        assert!(matches!(
            store.commit(&msg.encode_to_vec(), &msg, &values, &thread, "t".to_owned()),
            Err(Error::AnchorBinding { .. })
        ));
        assert!(store.thread_rows(&thread).unwrap().is_empty());
        assert!(store.resources(&thread).unwrap().is_empty());
    }

    #[test]
    fn threads_enumerates_transcript_files_and_index_maps_digests() {
        let store = store();
        let t1 = genesis_thread(0x11);
        let msg = sample_msg(vec![], "hello");
        let (row, _) = store
            .commit(
                &msg.encode_to_vec(),
                &msg,
                &sample_values("hello"),
                &t1,
                "t".to_owned(),
            )
            .unwrap();
        let threads = store.threads().unwrap();
        assert_eq!(threads, vec![t1.clone()]);
        let index = store.digest_index().unwrap();
        assert_eq!(
            index.get(
                crate::store::hex_to_bytes(&row.meta.digest)
                    .unwrap()
                    .as_slice()
            ),
            Some(&t1)
        );
    }

    #[test]
    fn thread_rows_of_an_unknown_thread_is_empty() {
        let store = store();
        assert!(store.thread_rows(&genesis_thread(0x99)).unwrap().is_empty());
    }
}
