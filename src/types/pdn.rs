use std::hash::Hash;

use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RelativeDistinguishedName};

use crate::certs::SessionId;
use crate::types::{DomainName, FederationId};
use crate::{
    OID_RDN_COMMON_NAME, OID_RDN_DOMAIN_COMPONENT, OID_RDN_UID, OID_RDN_UNIQUE_IDENTIFIER,
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
        let federation_id: AttributeTypeAndValue;
        let domain_name: AttributeTypeAndValue;
        let session_id: AttributeTypeAndValue;
        let additional_fields: AttributeTypeAndValue;
        for relative_distinguished_name in x509_distinguished_name.0.into_iter() {
            for attribute_value_and_item in relative_distinguished_name.0.iter() {
                match attribute_value_and_item.oid {
                    OID_RDN_COMMON_NAME => (),
                    OID_RDN_UID => (),
                    OID_RDN_UNIQUE_IDENTIFIER => (),
                    OID_RDN_DOMAIN_COMPONENT => (),
                    other => (),
                }
            }
        }
        todo!()
    }
}
