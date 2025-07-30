use std::hash::Hash;

use x509_cert::name::RelativeDistinguishedName;

use crate::certs::SessionId;
use crate::types::{DomainName, FederationId};

/// Higher-level abstraction of X.509 [distinguished names](https://ldap.com/ldap-dns-and-rdns/),
/// providing easier access to inner values compared to using [x509_cert::name::Name] in a raw manner.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PolyprotoDistinguishedName {
    /// A `pDN` with all necessary fields
    ActorDn(ActorDN),
    HomeServerDn(HomeServerDN),
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
