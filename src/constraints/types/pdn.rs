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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certs::SessionId;
    use crate::types::{DomainName, FederationId, local_name::LocalName};
    use x509_cert::name::RelativeDistinguishedName;

    fn create_valid_actor_dn() -> ActorDN {
        let federation_id = FederationId::new("alice@example.com").unwrap();
        let local_name = LocalName::new("alice").unwrap();
        let domain_name = DomainName::new("example.com").unwrap();
        let session_id = SessionId::new_validated("validSessionId123").unwrap();
        let additional_fields = RelativeDistinguishedName(der::asn1::SetOfVec::new());

        ActorDN {
            federation_id,
            local_name,
            domain_name,
            session_id,
            additional_fields,
        }
    }

    fn create_valid_home_server_dn() -> HomeServerDN {
        let domain_name = DomainName::new("example.com").unwrap();
        let additional_fields = RelativeDistinguishedName(der::asn1::SetOfVec::new());

        HomeServerDN {
            domain_name,
            additional_fields,
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn polyproto_distinguished_name_actor_with_actor_target_validates() {
        let actor_dn = create_valid_actor_dn();
        let pdn = PolyprotoDistinguishedName::ActorDn(actor_dn);

        assert!(pdn.validate(Some(Target::Actor)).is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn polyproto_distinguished_name_actor_with_none_target_validates() {
        let actor_dn = create_valid_actor_dn();
        let pdn = PolyprotoDistinguishedName::ActorDn(actor_dn);

        assert!(pdn.validate(None).is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn polyproto_distinguished_name_home_server_with_home_server_target_validates() {
        let home_server_dn = create_valid_home_server_dn();
        let pdn = PolyprotoDistinguishedName::HomeServerDn(home_server_dn);

        assert!(pdn.validate(Some(Target::HomeServer)).is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn polyproto_distinguished_name_home_server_with_none_target_validates() {
        let home_server_dn = create_valid_home_server_dn();
        let pdn = PolyprotoDistinguishedName::HomeServerDn(home_server_dn);

        assert!(pdn.validate(None).is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn polyproto_distinguished_name_actor_with_home_server_target_fails() {
        let actor_dn = create_valid_actor_dn();
        let pdn = PolyprotoDistinguishedName::ActorDn(actor_dn);

        let result = pdn.validate(Some(Target::HomeServer));
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, ConstraintError::Malformed(_)));
        assert!(error.to_string().contains("malformed"));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn polyproto_distinguished_name_home_server_with_actor_target_fails() {
        let home_server_dn = create_valid_home_server_dn();
        let pdn = PolyprotoDistinguishedName::HomeServerDn(home_server_dn);

        let result = pdn.validate(Some(Target::Actor));
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, ConstraintError::Malformed(_)));
        assert!(error.to_string().contains("malformed"));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn actor_dn_valid_components_validates() {
        let actor_dn = create_valid_actor_dn();

        assert!(actor_dn.validate(Some(Target::Actor)).is_ok());
        assert!(actor_dn.validate(None).is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn actor_dn_mismatched_local_name_fails() {
        let federation_id = FederationId::new("alice@example.com").unwrap();
        let local_name = LocalName::new("bob").unwrap(); // Mismatch!
        let domain_name = DomainName::new("example.com").unwrap();
        let session_id = SessionId::new_validated("validSessionId123").unwrap();
        let additional_fields = RelativeDistinguishedName(der::asn1::SetOfVec::new());

        let actor_dn = ActorDN {
            federation_id,
            local_name,
            domain_name,
            session_id,
            additional_fields,
        };

        let result = actor_dn.validate(None);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, ConstraintError::Malformed(_)));
        // The validation should fail because components don't match
        assert!(error.to_string().contains("malformed"));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn actor_dn_mismatched_domain_name_fails() {
        let federation_id = FederationId::new("alice@example.com").unwrap();
        let local_name = LocalName::new("alice").unwrap();
        let domain_name = DomainName::new("different.com").unwrap(); // Mismatch!
        let session_id = SessionId::new_validated("validSessionId123").unwrap();
        let additional_fields = RelativeDistinguishedName(der::asn1::SetOfVec::new());

        let actor_dn = ActorDN {
            federation_id,
            local_name,
            domain_name,
            session_id,
            additional_fields,
        };

        let result = actor_dn.validate(None);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, ConstraintError::Malformed(_)));
        // The validation should fail because components don't match
        assert!(error.to_string().contains("malformed"));
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn home_server_dn_valid_domain_validates() {
        let home_server_dn = create_valid_home_server_dn();

        assert!(home_server_dn.validate(None).is_ok());
        assert!(home_server_dn.validate(Some(Target::HomeServer)).is_ok());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn home_server_dn_invalid_domain_fails() {
        let invalid_domain = DomainName {
            value: String::new(),
        }; // Empty domain should fail
        let additional_fields = RelativeDistinguishedName(der::asn1::SetOfVec::new());

        let home_server_dn = HomeServerDN {
            domain_name: invalid_domain,
            additional_fields,
        };

        let result = home_server_dn.validate(None);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(matches!(error, ConstraintError::Malformed(_)));
        assert!(error.to_string().contains("malformed"));
    }
}
