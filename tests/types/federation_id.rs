use polyproto::types::FederationId;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_correct_federation_ids() {
    assert!(FederationId::new(" xenia@examle").is_err());
    assert!(FederationId::new("xenia@example").is_ok());
    assert!(FederationId::new("xenia@").is_err());
    assert!(FederationId::new("@example.com").is_err());
    assert!(FederationId::new("xenia.example.com").is_err());
    assert!(FederationId::new("xenia@example.com/").is_err());
    assert!(FederationId::new("xenia@example.com/1").is_err());
    assert!(FederationId::new("xenia@_example.com").is_err());
    assert!(FederationId::new("xenia@xn--grn-ioaaa.de").is_ok());
}
