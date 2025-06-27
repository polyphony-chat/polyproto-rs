use crate::Constrained;
use crate::types::x509_cert::SerialNumber;

impl Constrained for SerialNumber {
    fn validate(
        &self,
        _target: Option<crate::certs::Target>,
    ) -> Result<(), crate::errors::ConstraintError> {
        let serial_number_bytes = self.as_bytes();
        if serial_number_bytes.len() > 20 || serial_number_bytes.is_empty() {
            return Err(crate::errors::ConstraintError::OutOfBounds {
                    lower: 1,
                    upper: 20,
                    actual: serial_number_bytes.len().to_string(),
                    reason: "A serial number must not be longer than 20 octets and must be a positive, unsigned integer".to_string(),
                },
            );
        }
        Ok(())
    }
}
