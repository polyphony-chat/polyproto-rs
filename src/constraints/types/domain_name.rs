// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use regex::Regex;

use crate::types::{DomainName, REGEX_DOMAIN_NAME};

use super::*;

impl Constrained for DomainName {
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
        if self.value.trim().is_empty() {
            return Err(ConstraintError::Malformed(Some(
                "HomeServerDN must have a non-empty domain name".to_string(),
            )));
        }
        #[allow(clippy::unwrap_used)]
        let regex = Regex::new(REGEX_DOMAIN_NAME).unwrap();
        if regex.is_match(&self.value) {
            Ok(())
        } else {
            Err(ConstraintError::Malformed(Some(String::from(
                "Supplied domain name does not match regex",
            ))))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::Target;
    use crate::types::DomainName;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn domain_name_valid_formats_validate() {
        let test_cases = [
            "example.com",
            "subdomain.example.org",
            "multi-word.example.co.uk",
            "localhost",
            "example-domain.com",
            "a.b.c.d.e.com",
            "single",
        ];

        for case in test_cases {
            let domain_name = DomainName::new(case).unwrap();
            assert!(
                domain_name.validate(None).is_ok(),
                "DomainName '{}' should validate",
                case
            );
            assert!(
                domain_name.validate(Some(Target::Actor)).is_ok(),
                "DomainName '{}' should validate with Actor target",
                case
            );
            assert!(
                domain_name.validate(Some(Target::HomeServer)).is_ok(),
                "DomainName '{}' should validate with HomeServer target",
                case
            );
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn domain_name_empty_value_fails() {
        // Test that an empty domain name fails validation
        let empty_domain = DomainName {
            value: String::new(),
        };

        let result = empty_domain.validate(None);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, ConstraintError::Malformed(_)));
        assert!(error.to_string().contains("malformed"));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn domain_name_whitespace_only_fails() {
        // Test that whitespace-only domain name fails validation
        let whitespace_domain = DomainName {
            value: "   ".to_string(),
        };

        let result = whitespace_domain.validate(None);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, ConstraintError::Malformed(_)));
        assert!(error.to_string().contains("malformed"));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn domain_name_invalid_formats_fail_construction() {
        let invalid_cases = [
            "EXAMPLE.COM", // Uppercase not allowed
            "",            // Empty string
        ];

        for case in invalid_cases {
            let result = DomainName::new(case);
            assert!(
                result.is_err(),
                "DomainName construction should fail for invalid format: '{}'",
                case
            );
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn domain_name_regex_validation() {
        // Test regex validation specifically
        let valid_domain = DomainName::new("example.com").unwrap();
        assert!(valid_domain.validate(None).is_ok());

        // Create an invalid domain that bypasses constructor validation to test constraint validation
        let invalid_domain = DomainName {
            value: "INVALID.COM".to_string(),
        };

        let result = invalid_domain.validate(None);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, ConstraintError::Malformed(_)));
        assert!(error.to_string().contains("malformed"));
    }
}
