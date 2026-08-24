//! Public adaptive-resolution and layout-aware mutation vectors.

use secpref_kit::{
    compute_absent_mac, compute_mac, compute_super_mac, prefs, resolve_profile_policy,
    PolicyResolution, PreferenceLayout, SeedCandidate, SeedSource,
};
use serde_json::{json, Value};

const EXTENSION_ID: &str = "abcdefghijklmnopabcdefghijklmnop";

fn standard_profile(seed: &[u8], device_id: &str) -> Value {
    let record = json!({"location": 4, "state": 1});
    let record_path = format!("extensions.settings.{EXTENSION_ID}");
    let record_mac = compute_mac(seed, device_id, &record_path, &record);
    let absent_mac = compute_absent_mac(seed, device_id, "browser.absent_test");
    let mut profile = json!({
        "extensions": {"settings": {}},
        "browser": {},
        "protection": {"macs": {
            "extensions": {"settings": {}},
            "browser": {"absent_test": absent_mac}
        }}
    });
    profile["extensions"]["settings"][EXTENSION_ID] = record;
    profile["protection"]["macs"]["extensions"]["settings"][EXTENSION_ID] =
        Value::String(record_mac);
    let super_mac = compute_super_mac(seed, device_id, &profile["protection"]["macs"]);
    profile["protection"]["super_mac"] = Value::String(super_mac);
    profile
}

#[test]
fn public_resolver_proves_profile_without_browser_name() {
    let profile = standard_profile(b"", "device");
    let candidates = [SeedCandidate::provided([0x55; 64]), SeedCandidate::empty()];

    let PolicyResolution::Proven(policy) = resolve_profile_policy(&profile, "device", &candidates)
    else {
        panic!("expected complete profile proof");
    };

    assert_eq!(policy.layout, PreferenceLayout::standard());
    assert_eq!(policy.seed.source(), SeedSource::Empty);
    assert_eq!(policy.proof.checked_leaves, 2);
    assert!(policy.proof.super_mac_matched);
}

#[test]
fn public_layout_aware_api_writes_opera_store_only() {
    let layout = PreferenceLayout::opera();
    let seed = [0x66; 64];
    let mut profile = json!({});

    prefs::add_extension_with_layout(
        &mut profile,
        &layout,
        EXTENSION_ID,
        json!({"location": 4, "state": 1}),
        &seed,
        "device",
    )
    .unwrap();
    prefs::recompute_super_mac(&mut profile, &seed, "device").unwrap();

    assert!(profile["extensions"]["opsettings"]
        .get(EXTENSION_ID)
        .is_some());
    assert!(profile["extensions"].get("settings").is_none());
    assert_eq!(
        prefs::list_extensions_with_layout(&profile, &layout).len(),
        1
    );
}
