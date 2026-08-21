//! Extension-ID derivation coverage.

use secpref_kit::{derive_from_key, derive_from_path, resolve_ext_id, ExtId};

#[test]
fn from_key_matches_pinned_vector() {
    // base64 of 64 zero bytes → deterministic ID pinned to catch behaviour drift.
    let key = base64_encode_zeros(64);
    let id = derive_from_key(&key).unwrap();
    assert_eq!(id, "pfkfpnecnbgkcadachjiopgondajjhjl");
    assert_eq!(id.len(), 32);
}

#[test]
#[cfg(not(target_os = "windows"))]
fn from_path_linux_matches_pinned_vector() {
    assert_eq!(
        derive_from_path("/tmp/test_extension"),
        "abkadfbcnpenojlncdmkijflkbadnmeb"
    );
}

#[test]
fn from_key_rejects_non_base64() {
    let err = derive_from_key("!!!not base64!!!").unwrap_err();
    assert!(matches!(
        err,
        secpref_kit::SecPrefError::InvalidManifestKey(_)
    ));
}

#[test]
fn resolve_prefers_valid_key() {
    let key = base64_encode_zeros(64);
    let ext_id = resolve_ext_id(Some(&key), "/whatever/path");
    match ext_id {
        ExtId::FromKey(_) => {}
        ExtId::FromPath(_) => panic!("should have used the manifest key"),
    }
}

#[test]
fn resolve_falls_back_to_path_when_key_invalid() {
    let ext_id = resolve_ext_id(Some("not-base64!!!"), "/some/path");
    assert!(matches!(ext_id, ExtId::FromPath(_)));
}

#[test]
fn resolve_uses_path_when_no_key() {
    let ext_id = resolve_ext_id(None, "/some/path");
    assert!(matches!(ext_id, ExtId::FromPath(_)));
}

fn base64_encode_zeros(n: usize) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(vec![0u8; n])
}
