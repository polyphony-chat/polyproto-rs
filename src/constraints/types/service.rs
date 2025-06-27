// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::types::{Service, ServiceName};

use super::*;

impl Constrained for Service {
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        self.service.validate(target)
    }
}

impl Constrained for ServiceName {
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
        let stringified = self.to_string();
        if stringified.len() < 2 || stringified.len() > 64 {
            return Err(ConstraintError::OutOfBounds {
                lower: 2,
                upper: 64,
                actual: stringified.len().to_string(),
                reason: "The length of the ServiceName is outside of the allowed bounds"
                    .to_string(),
            });
        }
        let regex =
            regex::Regex::new(r"[^[:lower:][:digit:]\-_]").expect("Failed to compile regex!");
        if regex.is_match(&stringified) {
            return Err(ConstraintError::Malformed(Some(format!(
                "The ServiceName contains invalid characters: \"{stringified}\" contains characters that are not lowercase letters, digits, hyphens, or underscores"
            ))));
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn valid_service_names() {
        ServiceName::new("example").unwrap();
        ServiceName::new("example-1").unwrap();
        ServiceName::new("example_1").unwrap();
        ServiceName::new("example-1_2").unwrap();
        ServiceName::new("example-1_2-3").unwrap();
        ServiceName::new("e-x--a--___-m-----ple-1_2-3_4").unwrap();
        ServiceName::new("abcdefghijklmnopqrstuvwxyz_-0123456789").unwrap();
    }

    #[test]
    fn space_in_service_name() {
        assert!(ServiceName::new("example 1").is_err());
    }

    #[test]
    fn non_lowercase_characters_in_service_name() {
        assert!(ServiceName::new("Example").is_err());
        assert!(ServiceName::new("EXAMPLE").is_err());
        assert!(ServiceName::new("exAmple").is_err());
        assert!(ServiceName::new("exaMple").is_err());
        assert!(ServiceName::new("exampLe").is_err());
    }

    #[allow(clippy::invisible_characters)]
    #[test]
    fn non_latin_alphabet_characters_in_service_name() {
        assert!(ServiceName::new("🦀∄∄").is_err());
        assert!(ServiceName::new("🦀🦀🦀").is_err());
        assert!(ServiceName::new("∄∄∄").is_err());
        assert!(ServiceName::new("#cool_name").is_err());
        assert!(ServiceName::new("cool_name.").is_err());
        // Between the letters "l" and "n", there is a zero-width space character (U+200B).
        assert!(ServiceName::new("cool​name").is_err());
    }

    #[test]
    fn service_name_too_short() {
        assert!(ServiceName::new("a").is_err());
        assert!(ServiceName::new("aa").is_ok());
    }

    #[test]
    fn service_name_too_long() {
        assert!(
            ServiceName::new("12345678123456781234567812345678123456781234567812345678123456789")
                .is_err()
        );
        assert!(
            ServiceName::new("1234567812345678123456781234567812345678123456781234567812345678")
                .is_ok()
        );
    }
}
