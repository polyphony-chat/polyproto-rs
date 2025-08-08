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
