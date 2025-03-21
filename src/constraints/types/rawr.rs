use crate::Constrained;
use crate::types::ResourceAccessProperties;

impl Constrained for ResourceAccessProperties {
    fn validate(
        &self,
        _target: Option<crate::certs::Target>,
    ) -> Result<(), crate::errors::ConstraintError> {
        if self.private && self.public {
            Err(crate::errors::ConstraintError::Malformed(Some(
                "A resource must not be marked as private AND public".to_string(),
            )))
        } else {
            Ok(())
        }
    }
}
