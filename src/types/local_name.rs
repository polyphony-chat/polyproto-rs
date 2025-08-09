// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use x509_cert::attr::AttributeTypeAndValue;

use crate::errors::ConstraintError;
use crate::{Constrained, OID_RDN_COMMON_NAME};

/// Rust-flavor regular expression describing valid format for the local name of a Federation ID.
pub const REGEX_LOCAL_NAME: &str = r#"\b([a-z0-9._%+-]+)$"#;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize))]
/// A polyproto "Local Name"[(1)](https://polyproto.org/docs/protocols/core/#5-federation-ids-fids)[(2)](https://polyproto.org/docs/protocols/core/#6111-polyproto-distinguished-name-pdn)
/// is the instance-unique actor handle before the `@` in a [FederationId](crate::types::FederationId).
///
/// ## Example
///
/// In a `FederationId` of `xenia@example.com`, the local name would be `xenia`.
pub struct LocalName(pub(crate) String);

impl LocalName {
    /// Creates [Self], ensuring that `name` is a valid, acceptable `LocalName`.
    pub fn new(name: &str) -> Result<Self, ConstraintError> {
        let local_name = LocalName(name.to_owned());
        local_name.validate(None)?;
        Ok(local_name)
    }
}

impl std::fmt::Display for LocalName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for LocalName {
    type Err = ConstraintError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        LocalName::new(s)
    }
}

impl TryFrom<AttributeTypeAndValue> for LocalName {
    type Error = ConstraintError;

    fn try_from(value: AttributeTypeAndValue) -> Result<Self, Self::Error> {
        if value.oid != OID_RDN_COMMON_NAME {
            return Err(crate::errors::InvalidInput::Malformed(format!(
                "This value has OID {}, which does not match OID {OID_RDN_COMMON_NAME}",
                value.oid
            ))
            .into());
        }
        let attribute_value = value.value.value();
        let string = String::from_utf8_lossy(attribute_value);
        Self::new(&string)
    }
}

#[cfg(test)]
mod test {
    use der::Any;
    use x509_cert::ext::pkix::name::DirectoryString;

    use super::*;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn from_attribute_type_and_value() {
        let directory_string = DirectoryString::Utf8String(String::from("input"));
        let attribute_and_value = AttributeTypeAndValue {
            oid: OID_RDN_COMMON_NAME,
            value: Any::encode_from(&directory_string).unwrap(),
        };
        assert!(LocalName::try_from(attribute_and_value).is_ok());

        let directory_string = DirectoryString::Utf8String(String::from("input"));
        let attribute_and_value = AttributeTypeAndValue {
            oid: OID_RDN_COMMON_NAME,
            value: Any::encode_from(&directory_string).unwrap(),
        };
        assert!(LocalName::try_from(attribute_and_value).is_err())
    }
}
