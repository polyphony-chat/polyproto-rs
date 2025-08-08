use std::str::FromStr;

use crate::Constrained;
use crate::errors::ConstraintError;

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

impl FromStr for LocalName {
    type Err = ConstraintError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        LocalName::new(s)
    }
}
