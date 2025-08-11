// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;

impl Constrained for SessionId {
    /// [SessionId] must be longer than 0 and not longer than 32 characters to be deemed valid.
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
        let len = self.to_ia5string().len();
        if len > Length::new(32) || len == Length::ZERO {
            return Err(ConstraintError::OutOfBounds {
                lower: 1,
                upper: 32,
                actual: len.to_string(),
                reason: "SessionId too long".to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::{SessionId, Target};

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn session_id_valid_lengths_validate() {
        let test_cases = [
            "a",                                // 1 character (minimum)
            "short",                            // 5 characters
            "mediumLengthSessionId",            // 18 characters
            "12345678901234567890123456789012", // 32 characters (maximum)
        ];

        for case in test_cases {
            let session_id = SessionId::new_validated(case).unwrap();
            assert!(
                session_id.validate(None).is_ok(),
                "SessionId '{case}' should validate"
            );
            assert!(
                session_id.validate(Some(Target::Actor)).is_ok(),
                "SessionId '{case}' should validate with Actor target"
            );
            assert!(
                session_id.validate(Some(Target::HomeServer)).is_ok(),
                "SessionId '{case}' should validate with HomeServer target"
            );
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn session_id_empty_fails_construction() {
        let result = SessionId::new_validated("");
        assert!(result.is_err(), "Empty SessionId should fail construction");
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn session_id_too_long_fails_construction() {
        let too_long = "123456789012345678901234567890123"; // 33 characters
        let result = SessionId::new_validated(too_long);
        assert!(
            result.is_err(),
            "SessionId longer than 32 characters should fail construction"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn session_id_boundary_lengths() {
        // Test exact boundary conditions
        let exactly_32 = "12345678901234567890123456789012";
        assert_eq!(exactly_32.len(), 32);
        let session_id = SessionId::new_validated(exactly_32).unwrap();
        assert!(session_id.validate(None).is_ok());

        let exactly_1 = "a";
        assert_eq!(exactly_1.len(), 1);
        let session_id = SessionId::new_validated(exactly_1).unwrap();
        assert!(session_id.validate(None).is_ok());
    }
}
