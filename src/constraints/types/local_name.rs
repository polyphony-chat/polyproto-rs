use regex::Regex;

use crate::types::local_name::{LocalName, REGEX_LOCAL_NAME};

impl super::Constrained for LocalName {
    fn validate(
        &self,
        _target: Option<crate::certs::Target>,
    ) -> Result<(), crate::errors::ConstraintError> {
        #[allow(clippy::expect_used)]
        let regex = Regex::new(REGEX_LOCAL_NAME).expect("This Regex must never be invalid.");
        if regex.is_match(&self.0) {
            Ok(())
        } else {
            Err(super::ConstraintError::Malformed(Some(format!(
                "{} is not of allowed regex {REGEX_LOCAL_NAME}",
                self.0
            ))))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Constrained;
    use crate::certs::Target;
    use crate::types::local_name::LocalName;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn local_name_valid_formats_validate() {
        let test_cases = [
            "alice",
            "user123",
            "test.user",
            "user+tag",
            "user_name",
            "a",
            "user-name",
            "user%plus",
        ];

        for case in test_cases {
            let local_name = LocalName::new(case).unwrap();
            assert!(
                local_name.validate(None).is_ok(),
                "LocalName '{}' should validate",
                case
            );
            assert!(
                local_name.validate(Some(Target::Actor)).is_ok(),
                "LocalName '{}' should validate with Actor target",
                case
            );
            assert!(
                local_name.validate(Some(Target::HomeServer)).is_ok(),
                "LocalName '{}' should validate with HomeServer target",
                case
            );
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn local_name_invalid_formats_fail_construction() {
        let invalid_cases = [
            "ALICE", // Uppercase not allowed
            "",      // Empty string
        ];

        for case in invalid_cases {
            let result = LocalName::new(case);
            assert!(
                result.is_err(),
                "LocalName construction should fail for invalid format: '{}'",
                case
            );
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn local_name_edge_cases() {
        // Test edge cases that should be valid
        let edge_cases = [
            "a",              // Single character
            "123",            // Only numbers
            "user.name.long", // Multiple dots
            "user+test+more", // Multiple plus signs
            "user_test_more", // Multiple underscores
        ];

        for case in edge_cases {
            let local_name = LocalName::new(case).unwrap();
            assert!(
                local_name.validate(None).is_ok(),
                "LocalName edge case '{}' should validate",
                case
            );
        }
    }
}
