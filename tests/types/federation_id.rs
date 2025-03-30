// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use polyproto::types::{DomainName, FederationId};
use serde_json::{Value, from_value, to_value};

#[cfg(feature = "types")]
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

#[cfg(feature = "serde")]
#[cfg(feature = "types")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_fid_serde_serialize() {
    const NAME: &str = "xenia@example.com";
    let id = FederationId::new(NAME).unwrap();
    let json = to_value(id).unwrap();
    assert!(json.is_string());
    assert_eq!(json, Value::String(NAME.to_string()))
}

#[cfg(feature = "serde")]
#[cfg(feature = "types")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_fid_serde_deserialize() {
    use serde_json::from_value;

    const NAME: &str = "xenia@example.com";
    let json_value = Value::String(NAME.to_string());
    let id: FederationId = from_value(json_value).unwrap();
    assert_eq!(&id.to_string(), NAME);
}

#[cfg(feature = "serde")]
#[cfg(feature = "types")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_domain_name_serde_serialize() {
    const NAME: &str = "xenia@example.com";
    let domain_name = DomainName::new(NAME).unwrap();
    let json = to_value(domain_name).unwrap();
    assert!(json.is_string());
    assert_eq!(json, Value::String(NAME.to_string()));
}

#[cfg(feature = "serde")]
#[cfg(feature = "types")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_domain_name_serde_deserialize() {
    const NAME: &str = "xenia@example.com";
    let json_value = Value::String(NAME.to_string());
    let domain_name: DomainName = from_value(json_value).unwrap();
    assert_eq!(domain_name.to_string().as_str(), NAME);
}

#[cfg(feature = "serde")]
#[cfg(feature = "types")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_serde_serialize_identifier() {
    use polyproto::types::Identifer;

    const DOMAIN_NAME: &str = "example.com";
    const FEDERATION_ID: &str = "user@example.com";

    let instance_id = Identifer::Instance(DomainName::new(DOMAIN_NAME).unwrap());
    let federation_id = Identifer::FederationId(FederationId::new(FEDERATION_ID).unwrap());

    let instance_json = to_value(instance_id).unwrap();
    let federation_json = to_value(federation_id).unwrap();

    assert!(instance_json.is_string());
    assert_eq!(instance_json, Value::String(DOMAIN_NAME.to_string()));

    assert!(federation_json.is_string());
    assert_eq!(federation_json, Value::String(FEDERATION_ID.to_string()));
}

#[cfg(feature = "serde")]
#[cfg(feature = "types")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn test_serde_deserialize_identifier() {
    use polyproto::types::Identifer;

    const DOMAIN_NAME: &str = "example.com";
    const FEDERATION_ID: &str = "user@example.com";

    let instance_json_value = Value::String(DOMAIN_NAME.to_string());
    let federation_json_value = Value::String(FEDERATION_ID.to_string());

    let instance_id: Identifer = from_value(instance_json_value).unwrap();
    let federation_id: Identifer = from_value(federation_json_value).unwrap();

    match instance_id {
        Identifer::Instance(dn) => assert_eq!(dn.to_string().as_str(), DOMAIN_NAME),
        _ => panic!("Expected an Instance variant"),
    }

    match federation_id {
        Identifer::FederationId(fid) => assert_eq!(fid.to_string().as_str(), FEDERATION_ID),
        _ => panic!("Expected a FederationId variant"),
    }
}
