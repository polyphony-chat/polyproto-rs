use std::hash::Hash;

use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RelativeDistinguishedName};

use crate::certs::SessionId;
use crate::types::local_name::LocalName;
use crate::types::{DomainName, FederationId};
use crate::{
    Constrained, OID_RDN_COMMON_NAME, OID_RDN_DOMAIN_COMPONENT, OID_RDN_UID,
    OID_RDN_UNIQUE_IDENTIFIER,
};

/// Higher-level abstraction of X.509 [distinguished names](https://ldap.com/ldap-dns-and-rdns/),
/// providing easier access to inner values compared to using [x509_cert::name::Name] in a raw manner.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PolyprotoDistinguishedName {
    /// A `pDN` with all necessary fields for an actor.
    ActorDn(ActorDN),
    /// A `pDN` with all necessary fields for a home server.
    HomeServerDn(HomeServerDN),
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A [PolyprotoDistinguishedName] with all necessary fields for an actor certificate.
///
/// This struct is a higher-level abstraction of X.509 [distinguished names](https://ldap.com/ldap-dns-and-rdns/),
/// providing easier access to inner values compared to using [x509_cert::name::Name] in a raw manner.
pub struct ActorDN {
    federation_id: FederationId,
    domain_name: DomainName,
    session_id: SessionId,
    additional_fields: Vec<RelativeDistinguishedName>,
}

impl Hash for ActorDN {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.federation_id.hash(state);
        self.domain_name.hash(state);
        self.session_id.hash(state);
        self.additional_fields
            .iter()
            .for_each(|additional_field| additional_field.to_string().hash(state));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A [PolyprotoDistinguishedName] with all necessary fields for a home server certificate.
///
/// This struct is a higher-level abstraction of X.509 [distinguished names](https://ldap.com/ldap-dns-and-rdns/),
/// providing easier access to inner values compared to using [x509_cert::name::Name] in a raw manner.
pub struct HomeServerDN {
    domain_name: DomainName,
    additional_fields: Vec<RelativeDistinguishedName>,
}

impl Hash for HomeServerDN {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.domain_name.hash(state);
        self.additional_fields
            .iter()
            .for_each(|additional_field| additional_field.to_string().hash(state));
    }
}

impl TryFrom<Name> for ActorDN {
    type Error = crate::errors::InvalidInput;

    fn try_from(x509_distinguished_name: Name) -> Result<Self, Self::Error> {
        x509_distinguished_name
            .validate(Some(crate::certs::Target::Actor))
            .map_err(|e| crate::errors::InvalidInput::Malformed(e.to_string()))?;
        let mut maybe_federation_id: Option<AttributeTypeAndValue> = None;
        let mut maybe_local_name: Option<AttributeTypeAndValue> = None;
        let mut maybe_domain_names: Vec<AttributeTypeAndValue> = Vec::new();
        let mut maybe_session_id: Option<AttributeTypeAndValue> = None;
        let mut maybe_additional_fields: Vec<AttributeTypeAndValue> = Vec::new();
        for relative_distinguished_name in x509_distinguished_name.0.into_iter() {
            for attribute_value_and_item in relative_distinguished_name.0.iter() {
                match attribute_value_and_item.oid {
                    OID_RDN_COMMON_NAME => {
                        make_some_or_error(attribute_value_and_item, &mut maybe_local_name)?
                    }
                    OID_RDN_UID => {
                        make_some_or_error(attribute_value_and_item, &mut maybe_federation_id)?
                    }
                    OID_RDN_UNIQUE_IDENTIFIER => {
                        make_some_or_error(attribute_value_and_item, &mut maybe_session_id)?
                    }
                    OID_RDN_DOMAIN_COMPONENT => {
                        maybe_domain_names.push(attribute_value_and_item.clone())
                    }
                    _other => maybe_additional_fields.push(attribute_value_and_item.clone()),
                }
            }
        }
        // TODO: Ok now we have it all (hopefully); lets confirm that fact, turn the individual fields into their strongly typed counterparts and then return a full ActorDN!
        let federation_id = FederationId::try_from(match maybe_federation_id {
            Some(fid) => fid,
            None => {
                return Err(crate::errors::InvalidInput::Malformed(String::from(
                    "Expected Federation ID in ActorDN, found none",
                )));
            }
        })?;
        let local_name = LocalName::try_from(match maybe_local_name {
            Some(ln) => ln,
            None => {
                return Err(crate::errors::InvalidInput::Malformed(String::from(
                    "Expected Local Name in ActorDN, found none",
                )));
            }
        })?;
        let domain_name = DomainName::try_from(maybe_domain_names.as_slice())?;
        todo!()
    }
}

/// Helper function. Takes an exclusive reference `Option<AttributeTypeAndValue>`, inspects if it
/// holds a value, and
///
/// - Errors appropriately, if it already holds a value
/// - Else, updates the `None` value with the passed `attribute_value_and_item`, then returns `Ok(())`
fn make_some_or_error(
    attribute_value_and_item: &AttributeTypeAndValue,
    value_to_update: &mut Option<AttributeTypeAndValue>,
) -> Result<(), crate::errors::InvalidInput> {
    if value_to_update.is_none() {
        *value_to_update = Some(attribute_value_and_item.clone());
        Ok(())
    } else {
        Err(crate::errors::InvalidInput::Malformed(
            "Found multiple entries for same OID, where only one OID is allowed".to_owned(),
        ))
    }
}
