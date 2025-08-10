// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::types::pdn::{ActorDN, HomeServerDN, PolyprotoDistinguishedName};

use super::*;

impl Constrained for PolyprotoDistinguishedName {
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        match (self, target) {
            (PolyprotoDistinguishedName::ActorDn(actor_dn), Some(Target::Actor))
            | (PolyprotoDistinguishedName::ActorDn(actor_dn), None) => actor_dn.validate(target),
            (
                PolyprotoDistinguishedName::HomeServerDn(home_server_dn),
                Some(Target::HomeServer),
            )
            | (PolyprotoDistinguishedName::HomeServerDn(home_server_dn), None) => {
                home_server_dn.validate(target)
            }
            _ => Err(ConstraintError::Malformed(Some(format!(
                "Combination of target {target:?} and given PolyprotoDistinguishedName is invalid"
            )))),
        }
    }
}

impl Constrained for ActorDN {
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        // Validate all component fields
        self.federation_id.validate(target)?;
        self.local_name.validate(target)?;
        self.session_id.validate(target)?;
        self.domain_name.validate(target)?;

        // Additional validation specific to ActorDN structure
        // Ensure the local name matches the federation ID's local part
        if self.local_name != self.federation_id.local_name {
            return Err(ConstraintError::Malformed(Some(format!(
                "LocalName '{}' does not match federation ID local part '{}'",
                self.local_name, self.federation_id.local_name
            ))));
        }

        // Ensure the domain name matches the federation ID's domain part
        if self.domain_name != self.federation_id.domain_name {
            return Err(ConstraintError::Malformed(Some(format!(
                "DomainName '{}' does not match federation ID domain part '{}'",
                self.domain_name, self.federation_id.domain_name
            ))));
        }

        Ok(())
    }
}

impl Constrained for HomeServerDN {
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
        // DomainName validation is done at construction time via DomainName::new()

        // HomeServerDN should not have actor-specific fields
        // This is inherently satisfied by the structure, but we validate the domain
        self.domain_name.validate(None)
    }
}
