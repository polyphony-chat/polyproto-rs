// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
    FederationId::new("flori@polyphony.chat").unwrap();
    FederationId::new("a@localhost").unwrap();
    FederationId::new("really-long.domain.with-at-least-4-subdomains.or-something@example.com")
        .unwrap();
    assert!(FederationId::new("example@xn--638h.com").is_ok());
    assert!(FederationId::new("\\@example.com").is_err());
    assert!(FederationId::new("example.com").is_err());
    assert!(FederationId::new("examplecom").is_err());
    assert!(FederationId::new("⾆@example.com").is_err());
    assert!(FederationId::new("example@⾆.com").is_err());
    assert!(FederationId::new("example@😿.com").is_err());
}
