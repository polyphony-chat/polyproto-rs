// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::Ia5String;
use der::Length;
use log::debug;
use regex::Regex;
use x509_cert::name::{Name, RelativeDistinguishedName};

use crate::certs::capabilities::{Capabilities, KeyUsage};
use crate::certs::idcert::IdCert;
use crate::certs::idcerttbs::IdCertTbs;
use crate::certs::idcsr::IdCsr;
use crate::certs::{equal_domain_components, SessionId};
use crate::errors::base::ConstraintError;
use crate::key::PublicKey;
use crate::signature::Signature;
use crate::{
    Constrained, OID_RDN_COMMON_NAME, OID_RDN_DOMAIN_COMPONENT, OID_RDN_UID,
    OID_RDN_UNIQUE_IDENTIFIER,
};

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
    fn validate(&self) -> Result<(), ConstraintError> {
        // PRETTYFYME(bitfl0wer): This function is too long. Refactor it.
        let mut num_cn: u8 = 0;
        let mut num_dc: u8 = 0;
        let mut num_uid: u8 = 0;
        let mut num_unique_identifier: u8 = 0;
        let mut uid: RelativeDistinguishedName = RelativeDistinguishedName::default();
        let mut vec_dc: Vec<RelativeDistinguishedName> = Vec::new();

        let rdns = &self.0;
        for rdn in rdns.iter() {
            for item in rdn.0.iter() {
                match item.oid.to_string().as_str() {
                    OID_RDN_UID => {
                        num_uid += 1;
                        uid = rdn.clone();
                        let fid_regex =
                            Regex::new(r"\b([a-z0-9._%+-]+)@([a-z0-9-]+(\.[a-z0-9-]+)*)")
                                .expect("Regex failed to compile");
                        let string = String::from_utf8_lossy(item.value.value()).to_string();
                        if !fid_regex.is_match(&string) {
                            return Err(ConstraintError::Malformed(Some(
                                "Provided Federation ID (FID) in uid field seems to be invalid"
                                    .to_string(),
                            )));
                        }
                    }
                    OID_RDN_UNIQUE_IDENTIFIER => {
                        num_unique_identifier += 1;
                        if let Ok(value) =
                            Ia5String::new(&String::from_utf8_lossy(item.value.value()).to_string())
                        {
                            SessionId::new_validated(value)?;
                        } else {
                            return Err(ConstraintError::Malformed(Some(
                                "Tried to decode SessionID (uniqueIdentifier) as Ia5String and failed".to_string(),
                            )));
                        }
                    }
                    OID_RDN_COMMON_NAME => {
                        num_cn += 1;
                        if num_cn > 1 {
                            return Err(ConstraintError::OutOfBounds {
                                lower: 1,
                                upper: 1,
                                actual: num_cn.to_string(),
                                reason: "Distinguished Names must include exactly one common name attribute.".to_string()
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
        if num_dc == 0 {
            return Err(ConstraintError::OutOfBounds {
                lower: 1,
                upper: u8::MAX as i32,
                actual: "0".to_string(),
                reason: "Domain Component is missing".to_string(),
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

        // Only check if we are dealing with an actor
        if num_uid > 0 && num_unique_identifier > 0 {
            vec_dc.reverse(); // The order of the DCs is reversed in the [Name] object, starting with the TLD

            // Check if the domain components are equal between the UID and the DCs
            // First, remove the "username@" from the UID
            // We can unwrap, because an @ is guaranteed to be included in the string. The regex above
            // makes sure of that.
            let position_of_at = uid.to_string().find('@').unwrap();
            let uid_without_username = uid.to_string().split_at(position_of_at + 1).1.to_string(); // +1 to not include the @
            let dc_normalized_uid: Vec<&str> = uid_without_username.split('.').collect();
            dbg!(dc_normalized_uid.clone());
            let mut index = 0u8;
            for component in dc_normalized_uid.iter() {
                debug!("Checking if component \"{}\"...", component);
                let equivalent_dc = match vec_dc.get(index as usize) {
                    Some(dc) => dc,
                    None => {
                        return Err(ConstraintError::Malformed(Some(
                            "Domain Components do not equal the domain components in the UID"
                                .to_string(),
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
                        "Domain Components do not equal the domain components in the UID"
                            .to_string(),
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
        }
        Ok(())
    }
}

impl Constrained for SessionId {
    /// [SessionId] must be longer than 0 and not longer than 32 characters to be deemed valid.
    fn validate(&self) -> Result<(), ConstraintError> {
        if self.len() > Length::new(32) || self.len() == Length::ZERO {
            return Err(ConstraintError::OutOfBounds {
                lower: 1,
                upper: 32,
                actual: self.len().to_string(),
                reason: "SessionId too long".to_string(),
            });
        }
        Ok(())
    }
}

impl Constrained for Capabilities {
    fn validate(&self) -> Result<(), ConstraintError> {
        let is_ca = self.basic_constraints.ca;

        // Define the flags to check
        let mut can_commit_content = false;
        let mut can_sign = false;
        let mut key_cert_sign = false;
        let mut has_only_encipher = false;
        let mut has_only_decipher = false;
        let mut has_key_agreement = false;

        // Iterate over all the entries in the KeyUsage vector, check if they exist/are true
        for item in self.key_usage.key_usages.iter() {
            if !has_only_encipher && item == &KeyUsage::EncipherOnly {
                has_only_encipher = true;
            }
            if !has_only_decipher && item == &KeyUsage::DecipherOnly {
                has_only_decipher = true;
            }
            if !has_key_agreement && item == &KeyUsage::KeyAgreement {
                has_key_agreement = true;
            }
            if !has_key_agreement && item == &KeyUsage::ContentCommitment {
                can_commit_content = true;
            }
            if !has_key_agreement && item == &KeyUsage::DigitalSignature {
                can_sign = true;
            }
            if !has_key_agreement && item == &KeyUsage::KeyCertSign {
                key_cert_sign = true;
            }
        }

        // Non-CAs must be able to sign their messages. Whether with or without non-repudiation
        // does not matter.
        if !is_ca && !can_sign && !can_commit_content {
            return Err(ConstraintError::Malformed(Some(
                "Actors require signing capabilities, none found".to_string(),
            )));
        }

        // Certificates cannot be both non-repudiating and repudiating
        if can_sign && can_commit_content {
            return Err(ConstraintError::Malformed(Some(
                "Cannot have both signing and non-repudiation signing capabilities".to_string(),
            )));
        }

        // If these Capabilities are for a CA, it also must have the KeyCertSign Capability set to
        // true. Also, non-CAs are not allowed to have the KeyCertSign flag set to true.
        if is_ca || key_cert_sign {
            if !is_ca {
                return Err(ConstraintError::Malformed(Some(
                    "If KeyCertSign capability is wanted, CA flag must be true".to_string(),
                )));
            }
            if !key_cert_sign {
                return Err(ConstraintError::Malformed(Some(
                    "CA must have KeyCertSign capability".to_string(),
                )));
            }
        }

        // has_key_agreement needs to be true if has_only_encipher or _decipher are true.
        // See: <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.KeyUsage.encipher_only>
        // See: <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.KeyUsage.decipher_only>
        if (has_only_encipher || has_only_decipher) && !has_key_agreement {
            Err(ConstraintError::Malformed(Some(
                "KeyAgreement capability needs to be true to use OnlyEncipher or OnlyDecipher"
                    .to_string(),
            )))
        } else {
            Ok(())
        }
    }
}

impl<S: Signature, P: PublicKey<S>> Constrained for IdCsr<S, P> {
    fn validate(&self) -> Result<(), ConstraintError> {
        self.inner_csr.capabilities.validate()?;
        self.inner_csr.subject.validate()?;
        match self.inner_csr.subject_public_key.verify_signature(
            &self.signature,
            match &self.inner_csr.clone().to_der() {
                Ok(data) => data,
                Err(_) => return Err(ConstraintError::Malformed(Some("DER conversion failure when converting inner IdCsr to DER. IdCsr is likely malformed".to_string())))
            }
        ) {
            Ok(_) => (),
            Err(_) => return Err(ConstraintError::Malformed(Some("Provided signature does not match computed signature".to_string())))
        };
        Ok(())
    }
}

impl<S: Signature, P: PublicKey<S>> Constrained for IdCert<S, P> {
    fn validate(&self) -> Result<(), ConstraintError> {
        self.id_cert_tbs.validate()?;
        match self.id_cert_tbs.subject_public_key.verify_signature(
            &self.signature,
            match &self.id_cert_tbs.clone().to_der() {
                Ok(data) => data,
                Err(_) => {
                    return Err(ConstraintError::Malformed(Some(
                        "DER conversion failure when converting inner IdCertTbs to DER".to_string(),
                    )));
                }
            },
        ) {
            Ok(_) => Ok(()),
            Err(_) => Err(ConstraintError::Malformed(Some(
                "Provided signature does not match computed signature".to_string(),
            ))),
        }
    }
}

impl<S: Signature, P: PublicKey<S>> Constrained for IdCertTbs<S, P> {
    fn validate(&self) -> Result<(), ConstraintError> {
        self.capabilities.validate()?;
        self.issuer.validate()?;
        self.subject.validate()?;
        match equal_domain_components(&self.issuer, &self.subject) {
            true => (),
            false => {
                return Err(ConstraintError::Malformed(Some(
                    "Domain components of issuer and subject are not equal".to_string(),
                )))
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod name_constraints {
    use std::str::FromStr;

    use x509_cert::name::Name;

    use crate::testing_utils::init_logger;
    use crate::Constrained;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn correct() {
        init_logger();
        let name = Name::from_str(
            "cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=h3g2jt4dhfgj8hjs",
        )
        .unwrap();
        name.validate().unwrap();
        let name = Name::from_str("CN=flori,DC=www,DC=polyphony,DC=chat").unwrap();
        name.validate().unwrap();
        let name = Name::from_str(
            "cn=flori,dc=some,dc=domain,dc=that,dc=is,dc=quite,dc=long,dc=geez,dc=thats,dc=alotta,dc=subdomains,dc=example,dc=com,uid=flori@some.domain.that.is.quite.long.geez.thats.alotta.subdomains.example.com,uniqueIdentifier=h3g2jt4dhfgj8hjs",
        )
        .unwrap();
        name.validate().unwrap();
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn mismatch_uid_dcs() {
        init_logger();
        let name = Name::from_str(
            "cn=flori,dc=some,dc=domain,dc=that,dc=is,dc=quite,dc=long,dc=geez,dc=alotta,dc=subdomains,dc=example,dc=com,uid=flori@some.domain.that.is.quite.long.geez.thats.alotta.subdomains.example.com,uniqueIdentifier=h3g2jt4dhfgj8hjs",
        )
        .unwrap();
        name.validate().err().unwrap();

        let name = Name::from_str(
            "cn=flori,dc=some,dc=domain,dc=that,dc=is,dc=quite,dc=long,dc=geez,dc=alotta,dc=subdomains,dc=example,dc=com,uid=flori@domain.that.is.quite.long.geez.thats.alotta.subdomains.example.com,uniqueIdentifier=h3g2jt4dhfgj8hjs",
        )
        .unwrap();
        name.validate().err().unwrap();
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn no_domain_component() {
        init_logger();
        let name = Name::from_str("CN=flori").unwrap();
        assert!(name.validate().is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn two_cns() {
        init_logger();
        let name = Name::from_str("CN=flori,CN=xenia,DC=localhost").unwrap();
        assert!(name.validate().is_err())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn two_uid_or_uniqueid() {
        init_logger();
        let name = Name::from_str("CN=flori,CN=xenia,uid=numbaone,uid=numbatwo").unwrap();
        assert!(name.validate().is_err());
        let name =
            Name::from_str("CN=flori,CN=xenia,uniqueIdentifier=numbaone,uniqueIdentifier=numbatwo")
                .unwrap();
        assert!(name.validate().is_err())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn uid_and_no_uniqueid_or_uniqueid_and_no_uid() {
        init_logger();
        let name = Name::from_str("CN=flori,CN=xenia,uid=numbaone").unwrap();
        assert!(name.validate().is_err());
        let name = Name::from_str("CN=flori,CN=xenia,uniqueIdentifier=numbaone").unwrap();
        assert!(name.validate().is_err())
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn malformed_session_id_fails() {
        init_logger();
        let name =
            Name::from_str("cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=").unwrap();
        assert!(name.validate().is_err());
        let name =
            Name::from_str("cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=123456789012345678901234567890123").unwrap();
        assert!(name.validate().is_err());
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn malformed_uid_fails() {
        init_logger();
        let name =
            Name::from_str("cn=flori,dc=localhost,uid=\"flori@\",uniqueIdentifier=3245").unwrap();
        assert!(name.validate().is_err());
        let name =
            Name::from_str("cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=3245")
                .unwrap();
        assert!(name.validate().is_ok());
        let name = Name::from_str("cn=flori,dc=localhost,uid=\"1\",uniqueIdentifier=3245").unwrap();
        assert!(name.validate().is_err());
    }
}

#[cfg(test)]
mod session_id_constraints {

    use der::asn1::Ia5String;

    use crate::certs::SessionId;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn zero_long_session_id_fails() {
        assert!(SessionId::new_validated(Ia5String::new("".as_bytes()).unwrap()).is_err())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn thirtytwo_length_session_id_is_ok() {
        assert!(SessionId::new_validated(
            Ia5String::new("11111111111111111111111111222222".as_bytes()).unwrap()
        )
        .is_ok())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn thirtythree_length_session_id_fails() {
        assert!(SessionId::new_validated(
            Ia5String::new("111111111111111111111111112222223".as_bytes()).unwrap()
        )
        .is_err())
    }
}
