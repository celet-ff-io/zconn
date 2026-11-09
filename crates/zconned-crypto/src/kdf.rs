//! Key derivation over KMAC256 (single-stage PRF).

use sha3_kmac::Kmac256;

/// Derive `out.len()` bytes: one KMAC256 evaluation keyed by
/// `key`, domain-separated by the customization string `label`,
/// absorbing `data` (e.g. `derive(master, b"zconned/v1/sign",
/// &[], ...)` for the identity's derived keys).
pub fn derive(key: &[u8; 32], label: &[u8], data: &[u8], out: &mut [u8]) {
    let mut mac = Kmac256::new(key, label).expect("32-byte key meets the KMAC256 minimum");
    mac.update(data);
    mac.finalize_into(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::{assert_eq, assert_ne};

    #[test]
    fn deterministic_for_same_master_and_label() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        derive(&[7u8; 32], b"zconned/v1/sign", &[], &mut a);
        derive(&[7u8; 32], b"zconned/v1/sign", &[], &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn labels_are_domain_separated() {
        let mut ed = [0u8; 32];
        let mut x = [0u8; 32];
        derive(&[7u8; 32], b"zconned/v1/sign", &[], &mut ed);
        derive(&[7u8; 32], b"zconned/v1/static_dh", &[], &mut x);
        assert_ne!(ed, x);
    }

    #[test]
    fn masters_are_separated() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        derive(&[7u8; 32], b"zconned/v1/sign", &[], &mut a);
        derive(&[8u8; 32], b"zconned/v1/sign", &[], &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn output_length_is_flexible() {
        // Different lengths are independent squeezes, not a prefix
        // relation.
        let mut long = [0u8; 64];
        let mut short = [0u8; 32];
        derive(&[7u8; 32], b"zconned/v1/test", &[], &mut long);
        derive(&[7u8; 32], b"zconned/v1/test", &[], &mut short);
        assert_ne!(&long[..32], &short[..]);
    }
}
