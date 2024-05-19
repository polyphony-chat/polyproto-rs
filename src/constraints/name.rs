// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::errors::ERR_MSG_DC_UID_MISMATCH;

use super::*;

impl Constrained for Name {
    /// [Name] must meet the following criteria to be valid in the context of polyproto:
    /// - Distinguished name MUST have "common name" attribute, which is equal to the actor or
    ///   home server name of the subject in question. Only one "common name" is allowed.
    /// - MUST have AT LEAST one domain component, specifying the home server domain for this
    ///   entity.
    /// - If actor name, MUST include UID (OID 0.9.2342.19200300.100.1.1) and uniqueIdentifier
    ///   (OID 0.9.2342.19200300.100.1.44).
    ///     - UID is the federation ID of the actor.
    ///     - uniqueIdentifier is the [SessionId] of the actor.
    /// - MAY have "organizational unit" attributes
    /// - MAY have other attributes, which might be ignored by other home servers and other clients.
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        let mut num_cn: u8 = 0;
        let mut num_dc: u8 = 0;
        let mut num_uid: u8 = 0;
        let mut num_unique_identifier: u8 = 0;
        let mut vec_dc: Vec<RelativeDistinguishedName> = Vec::new();
        let mut uid: RelativeDistinguishedName = RelativeDistinguishedName::default();

        let rdns = &self.0;
        for rdn in rdns.iter() {
            for item in rdn.0.iter() {
                match item.oid.to_string().as_str() {
                    OID_RDN_UID => {
                        num_uid += 1;
                        uid = rdn.clone();
                        validate_rdn_uid(item)?;
                    }
                    OID_RDN_UNIQUE_IDENTIFIER => {
                        num_unique_identifier += 1;
                        validate_rdn_unique_identifier(item)?;
                    }
                    OID_RDN_COMMON_NAME => {
                        num_cn += 1;
                        if num_cn > 1 {
                            return Err(ConstraintError::OutOfBounds {
                                lower: 1,
                                upper: 1,
                                actual: num_cn.to_string(),
                                reason: "Distinguished Names must not contain more than one Common Name field".to_string()
                            });
                        }
                    }
                    OID_RDN_DOMAIN_COMPONENT => {
                        num_dc += 1;
                        vec_dc.push(rdn.clone());
                    }
                    _ => {}
                }
            }
        }
        // The order of the DCs is reversed in the [Name] object, compared to the order of the DCs in the UID.
        vec_dc.reverse();
        if let Some(target) = target {
            match target {
                Target::Actor => validate_dc_matches_dc_in_uid(vec_dc, uid)?,
                Target::HomeServer => {
                    if num_uid > 0 || num_unique_identifier > 0 {
                        return Err(ConstraintError::OutOfBounds {
                            lower: 0,
                            upper: 0,
                            actual: "1".to_string(),
                            reason: "Home Servers must not have UID or uniqueIdentifier"
                                .to_string(),
                        });
                    }
                }
            };
        } else if num_uid != 0 {
            validate_dc_matches_dc_in_uid(vec_dc, uid)?;
        }

        if num_dc == 0 {
            return Err(ConstraintError::OutOfBounds {
                lower: 1,
                upper: u8::MAX as i32,
                actual: "0".to_string(),
                reason: "Domain Component is missing in Name component".to_string(),
            });
        }
        if num_uid > 1 {
            return Err(ConstraintError::OutOfBounds {
                lower: 0,
                upper: 1,
                actual: num_uid.to_string(),
                reason: "Too many UID components supplied".to_string(),
            });
        }
        if num_unique_identifier > 1 {
            return Err(ConstraintError::OutOfBounds {
                lower: 0,
                upper: 1,
                actual: num_unique_identifier.to_string(),
                reason: "Too many uniqueIdentifier components supplied".to_string(),
            });
        }
        if num_unique_identifier > 0 && num_uid == 0 {
            return Err(ConstraintError::OutOfBounds {
                lower: 1,
                upper: 1,
                actual: num_uid.to_string(),
                reason: "Actors must have uniqueIdentifier AND UID, only uniqueIdentifier found"
                    .to_string(),
            });
        }
        if num_uid > 0 && num_unique_identifier == 0 {
            return Err(ConstraintError::OutOfBounds {
                lower: 1,
                upper: 1,
                actual: num_unique_identifier.to_string(),
                reason: "Actors must have uniqueIdentifier AND UID, only UID found".to_string(),
            });
        }
        Ok(())
    }
}

/// Check if the domain components are equal between the UID and the DCs
fn validate_dc_matches_dc_in_uid(
    vec_dc: Vec<RelativeDistinguishedName>,
    uid: RelativeDistinguishedName,
) -> Result<(), ConstraintError> {
    // Find the position of the @ in the UID
    let position_of_at = match uid.to_string().find('@') {
        Some(pos) => pos,
        None => {
            return Err(ConstraintError::Malformed(Some(
                "UID does not contain an @".to_string(),
            )))
        }
    };
    // Split the UID at the @
    let uid_without_username = uid.to_string().split_at(position_of_at + 1).1.to_string(); // +1 to not include the @
    let dc_normalized_uid: Vec<&str> = uid_without_username.split('.').collect();
    dbg!(dc_normalized_uid.clone());
    let mut index = 0u8;
    // Iterate over the DCs in the UID and check if they are equal to the DCs in the DCs
    for component in dc_normalized_uid.iter() {
        debug!("Checking if component \"{}\"...", component);
        let equivalent_dc = match vec_dc.get(index as usize) {
            Some(dc) => dc,
            None => {
                return Err(ConstraintError::Malformed(Some(
                    ERR_MSG_DC_UID_MISMATCH.to_string(),
                )))
            }
        };
        let equivalent_dc = equivalent_dc.to_string().split_at(3).1.to_string();
        debug!(
            "...is equal to component \"{}\"...",
            equivalent_dc.to_string()
        );
        if component != &equivalent_dc.to_string() {
            return Err(ConstraintError::Malformed(Some(
                ERR_MSG_DC_UID_MISMATCH.to_string(),
            )));
        }
        index = match index.checked_add(1) {
            Some(i) => i,
            None => {
                return Err(ConstraintError::Malformed(Some(
                    "More than 255 Domain Components found".to_string(),
                )))
            }
        };
    }
    Ok(())
}

use log::debug;
use x509_cert::attr::AttributeTypeAndValue;

fn validate_rdn_uid(item: &AttributeTypeAndValue) -> Result<(), ConstraintError> {
    let fid_regex = Regex::new(r"\b([a-z0-9._%+-]+)@([a-z0-9-]+(\.[a-z0-9-]+)*)")
        .expect("Regex failed to compile");
    let string = String::from_utf8_lossy(item.value.value()).to_string();
    if !fid_regex.is_match(&string) {
        Err(ConstraintError::Malformed(Some(
            "Provided Federation ID (FID) in uid field seems to be invalid".to_string(),
        )))
    } else {
        Ok(())
    }
}

fn validate_rdn_unique_identifier(item: &AttributeTypeAndValue) -> Result<(), ConstraintError> {
    if let Ok(value) = Ia5String::new(&String::from_utf8_lossy(item.value.value()).to_string()) {
        SessionId::new_validated(value)?;
        Ok(())
    } else {
        Err(ConstraintError::Malformed(Some(
            "Tried to decode SessionID (uniqueIdentifier) as Ia5String and failed".to_string(),
        )))
    }
}
