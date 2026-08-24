//! Extension-ID derivation coverage.

use secpref_kit::derive_from_path;
use secpref_kit::{derive_from_key, resolve_ext_id, ExtId};

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
#[cfg(target_os = "windows")]
fn from_path_windows_normalizes_drive_and_matches_pinned_vector() {
    assert_eq!(
        derive_from_path(r"c:\Users\Test\ext"),
        "oockkaflpokdeofhojmcfddhbikodiam"
    );
    assert_eq!(
        derive_from_path(r"c:\Users\Test\ext"),
        derive_from_path(r"C:\Users\Test\ext")
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
fn from_key_rejects_empty_input() {
    let error = derive_from_key("").unwrap_err();
    assert!(matches!(
        error,
        secpref_kit::SecPrefError::InvalidManifestKey(_)
    ));
}

#[test]
fn from_key_accepts_pem_wrapper() {
    let encoded = base64_encode_zeros(64);
    let pem = format!("-----BEGIN PUBLIC KEY-----\n{encoded}\n-----END PUBLIC KEY-----");
    assert_eq!(
        derive_from_key(&pem).unwrap(),
        derive_from_key(&encoded).unwrap()
    );
}

#[test]
fn resolve_prefers_valid_key() {
    let key = base64_encode_zeros(64);
    let ext_id = resolve_ext_id(Some(&key), "/whatever/path").unwrap();
    match ext_id {
        ExtId::FromKey(_) => {}
        ExtId::FromPath(_) => panic!("should have used the manifest key"),
    }
}

#[test]
fn resolve_rejects_invalid_present_key() {
    let error = resolve_ext_id(Some("not-base64!!!"), "/some/path").unwrap_err();
    assert!(matches!(
        error,
        secpref_kit::SecPrefError::InvalidManifestKey(_)
    ));
}

#[test]
fn resolve_uses_path_when_no_key() {
    let ext_id = resolve_ext_id(None, "/some/path").unwrap();
    assert!(matches!(ext_id, ExtId::FromPath(_)));
}

fn base64_encode_zeros(n: usize) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(vec![0u8; n])
}
