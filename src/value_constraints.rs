// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::Length;
use spki::ObjectIdentifier;
use x509_cert::name::Name;

use crate::certs::SessionId;
use crate::Constrained;

impl Constrained for Name {
    /// [Name] must meet the following criteria to be valid in the context of polyproto:
    /// - Distinguished name MUST have "common name" attribute, which is equal to the actor or
    ///   home server name of the subject in question. Only one "common name" is allowed.
    /// - MUST have AT LEAST one domain component, specifying the home server subdomain for this
    ///   entity.
    /// - If actor name, MUST include UID (OID 0.9.2342.19200300.100.1.1) and uniqueIdentifier
    ///   (OID 0.9.2342.19200300.100.1.44).
    ///     - UID is the federation ID of the actor.
    ///     - uniqueIdentifier is the [SessionId] of the actor.
    /// - MAY have "organizational unit" attributes
    /// - MAY have other attributes, which might be ignored by other home servers and other clients.
    fn validate(&self) -> Result<(), crate::ConstraintError> {
        // this code sucks. i couldn't think of a way to make it better though. sorry!
        let mut num_cn: u8 = 0;
        let mut num_dc: u8 = 0;
        let mut num_uid: u8 = 0;
        let mut num_unique_identifier: u8 = 0;
        let oid_common_name = ObjectIdentifier::from_str("2.5.4.3")
            .expect("The OID for \"Common Name\" is invalid. Please report this bug to https://github.com/polyphony-chat/polyproto");
        let oid_domain_component = ObjectIdentifier::from_str("0.9.2342.19200300.100.1.25")
            .expect("The OID for \"Domain Component\" is invalid. Please report this bug to https://github.com/polyphony-chat/polyproto");
        let oid_uid = ObjectIdentifier::from_str("0.9.2342.19200300.100.1.1")
            .expect("The OID for \"UID\" is invalid. Please report this bug to https://github.com/polyphony-chat/polyproto");
        let oid_unique_identifier = ObjectIdentifier::from_str("0.9.2342.19200300.100.1.44")
            .expect("The OID for \"Unique Identifier\" is invalid. Please report this bug to https://github.com/polyphony-chat/polyproto");

        let rdns = &self.0;
        for rdn in rdns.iter() {
            for item in rdn.0.iter() {
                if item.oid == oid_common_name {
                    num_cn += 1;
                    if num_cn > 1 {
                        return Err(crate::ConstraintError::OutOfBounds {
                            lower: 1,
                            upper: 1,
                            actual: num_cn.to_string(),
                        });
                    }
                } else if item.oid == oid_domain_component {
                    num_dc += 1;
                }
            }
        }
        if num_dc == 0 {
            return Err(crate::ConstraintError::OutOfBounds {
                lower: 1,
                upper: u8::MAX as i32,
                actual: "0".to_string(),
            });
        }
        Ok(())
    }
}

impl Constrained for SessionId {
    /// [SessionId] must be longer than 0 and not longer than 32 characters to be deemed valid.
    fn validate(&self) -> Result<(), crate::ConstraintError> {
        if self.len() > Length::new(32) || self.len() == Length::ZERO {
            return Err(crate::ConstraintError::OutOfBounds {
                lower: 1,
                upper: 32,
                actual: self.len().to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod name_constraints {
    use std::str::FromStr;

    use x509_cert::name::Name;

    use crate::Constrained;

    #[test]
    fn correct() {
        let name = Name::from_str("CN=flori,DC=localhost,UID=h3g2jt4dhfgj8hjs").unwrap();
        name.validate().unwrap();
        let name = Name::from_str("CN=flori,DC=www,DC=polyphony,DC=chat").unwrap();
        name.validate().unwrap();
    }

    #[test]
    fn no_domain_component() {
        let name = Name::from_str("CN=flori").unwrap();
        assert!(name.validate().is_err());
    }

    #[test]
    fn two_cns() {
        let name = Name::from_str("CN=flori,CN=xenia,DC=localhost").unwrap();
        assert!(name.validate().is_err())
    }
}

#[cfg(test)]
mod session_id_constraints {
    use der::asn1::Ia5String;

    use crate::certs::SessionId;

    #[test]
    fn zero_long_session_id_fails() {
        assert!(SessionId::new(Ia5String::new("").unwrap()).is_err())
    }

    #[test]
    fn thirtytwo_length_session_id_is_ok() {
        assert!(SessionId::new(Ia5String::new("11111111111111111111111111222222").unwrap()).is_ok())
    }

    #[test]
    fn thirtythree_length_session_id_fails() {
        assert!(
            SessionId::new(Ia5String::new("111111111111111111111111112222223").unwrap()).is_err()
        )
    }
}
