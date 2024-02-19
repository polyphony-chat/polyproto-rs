// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use spki::ObjectIdentifier;
use x509_cert::name::Name;

use crate::Constrained;

impl Constrained for Name {
    /// [Name] must meet the following criteria to be valid in the context of polyproto:
    /// - Distinguished name MUST have "common name" attribute, which is equal to the actor or
    ///   home server name of the subject in question. Only one "common name" is allowed.
    /// - MUST have AT LEAST one domain component, specifying the home server subdomain for this
    ///   entity.
    /// - MAY have "organizational unit" attributes
    /// - MAY have other attributes, which might be ignored by other home servers and other clients.
    fn validate(&self) -> Result<(), crate::ConstraintError> {
        let mut num_cn: u8 = 0;
        let mut num_dc: u8 = 0;
        let oid_common_name = ObjectIdentifier::from_str("2.5.4.3")
            .expect("Please report this bug to https://github.com/polyphony-chat/polyproto");
        let oid_domain_component = ObjectIdentifier::from_str("0.9.2342.19200300.100.1.25")
            .expect("Please report this bug to https://github.com/polyphony-chat/polyproto");
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
