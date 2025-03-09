// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use polyproto::errors::ConversionError;

#[cfg(feature = "reqwest")]
pub(crate) mod api;
pub(crate) mod certs;
pub(crate) mod common;
#[cfg(feature = "gateway")]
pub(crate) mod gateway;
#[cfg(feature = "types")]
pub(crate) mod types;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn conversion_error_from_oid_error() {
    let oid_error =
        der::oid::ObjectIdentifier::new("this isn't valid in any sense of the imagination")
            .unwrap_err();
    let our_error = ConversionError::from(oid_error);
    let inner_error = match our_error {
        ConversionError::ConstOidError(error) => error,
        _ => panic!(),
    };
    assert_eq!(inner_error, oid_error)
}
