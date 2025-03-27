// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::types::DomainName as RDomainName;
use crate::types::FederationId as RFederationId;
use wasm_bindgen::prelude::*;

use super::errors::JsConstraintError;

#[derive(Clone, Debug)]
#[wasm_bindgen(inspectable)]
/// A `FederationId` is a globally unique identifier for an actor in the context of polyproto.
pub struct FederationId {
    #[wasm_bindgen(skip)]
    _inner: RFederationId,
}

#[wasm_bindgen]
impl FederationId {
    #[wasm_bindgen(constructor)]
    /// Validates input, then creates a new `FederationId`. Throws an error if input validation fails.
    pub fn new(id: &str) -> Result<FederationId, JsConstraintError> {
        Ok(FederationId {
            _inner: RFederationId::new(id).map_err(|_| JsConstraintError::InvalidInput)?,
        })
    }

    #[wasm_bindgen(js_name = "toJSON")]
    pub fn js_to_json(&self) -> String {
        self._inner.to_string()
    }
}

#[derive(Debug, Clone)]
#[wasm_bindgen(inspectable)]
pub struct DomainName {
    #[wasm_bindgen(skip)]
    _inner: RDomainName,
}
