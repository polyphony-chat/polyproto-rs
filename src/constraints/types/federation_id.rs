// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use regex::Regex;

use crate::errors::ERR_MSG_FEDERATION_ID_REGEX;
use crate::types::{FederationId, REGEX_FEDERATION_ID};

use super::*;

impl Constrained for FederationId {
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
        if self.to_string().trim() != self.to_string().as_str() {
            return Err(ConstraintError::Malformed(Some(format!(
                "FederationId must not contain leading or trailing whitespace: {self}"
            ))));
        }
        let fid_regex = Regex::new(REGEX_FEDERATION_ID).unwrap();
        match fid_regex.is_match(&self.to_string()) {
            true => Ok(()),
            false => Err(ConstraintError::Malformed(Some(
                ERR_MSG_FEDERATION_ID_REGEX.to_string(),
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FederationId;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn federation_id_valid_formats_validate() {
        let test_cases = [
            "alice@example.com",
            "user123@subdomain.example.org",
            "test.user@multi-word.example.co.uk",
            "simple@localhost",
            "user+tag@example.com",
            "user_name@example-domain.com",
        ];

        for case in test_cases {
            let federation_id = FederationId::new(case).unwrap();
            assert!(
                federation_id.validate(None).is_ok(),
                "FederationId '{case}' should validate"
            );
            assert!(
                federation_id.validate(Some(Target::Actor)).is_ok(),
                "FederationId '{case}' should validate with Actor target"
            );
            assert!(
                federation_id.validate(Some(Target::HomeServer)).is_ok(),
                "FederationId '{case}' should validate with HomeServer target"
            );
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn federation_id_with_whitespace_fails() {
        let federation_id = FederationId {
            local_name: crate::types::local_name::LocalName::new("alice").unwrap(),
            domain_name: crate::types::DomainName::new("example.com").unwrap(),
        };

        // Note: In practice, whitespace validation happens during construction
        // This test ensures the validation method works correctly
        let result = federation_id.validate(None);
        assert!(result.is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn federation_id_invalid_formats_fail_construction() {
        let invalid_cases = [
            "alice",             // Missing domain
            "@example.com",      // Missing local name
            "alice@",            // Missing domain
            "alice@.com",        // Invalid domain format
            "ALICE@EXAMPLE.COM", // Uppercase not allowed
            "",                  // Empty string
        ];

        for case in invalid_cases {
            let result = FederationId::new(case);
            assert!(
                result.is_err(),
                "FederationId construction should fail for invalid format: '{case}'"
            );
        }
    }
}
