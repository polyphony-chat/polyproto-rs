// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use log::{debug, warn};

use crate::errors::{
    ERR_MSG_ACTOR_CANNOT_BE_CA, ERR_MSG_DC_MISMATCH_ISSUER_SUBJECT,
    ERR_MSG_HOME_SERVER_MISSING_CA_ATTR, ERR_MSG_SIGNATURE_MISMATCH,
};

use super::*;

impl<S: Signature, P: PublicKey<S>> Constrained for IdCsrInner<S, P> {
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        log::trace!("[IdCsrInner::validate()] validating capabilities for target: {target:?}");
        self.capabilities.validate(target)?;
        log::trace!("[IdCsrInner::validate()] validating subject for target: {target:?}");
        self.subject.validate(target)?;
        if let Some(target) = target {
            match target {
                Target::Actor => {
                    if self.capabilities.basic_constraints.ca {
                        return Err(ConstraintError::Malformed(Some(
                            ERR_MSG_ACTOR_CANNOT_BE_CA.to_string(),
                        )));
                    }
                }
                Target::HomeServer => {
                    if !self.capabilities.basic_constraints.ca {
                        return Err(ConstraintError::Malformed(Some(
                            ERR_MSG_HOME_SERVER_MISSING_CA_ATTR.to_string(),
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}

impl<S: Signature, P: PublicKey<S>> Constrained for IdCsr<S, P> {
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        log::trace!("[IdCsr::validate()] validating inner CSR with target {target:?}");
        self.inner_csr.validate(target)?;
        log::trace!("[IdCsr::validate()] verifying signature");
        match self.inner_csr.subject_public_key.verify_signature(
            &self.signature,
            match &self.inner_csr.clone().to_der() {
                Ok(data) => data,
                Err(_) => {
                    log::warn!("[IdCsr::validate()] DER conversion failure when converting inner IdCsr to DER. IdCsr is likely malformed");
                    return Err(ConstraintError::Malformed(Some("DER conversion failure when converting inner IdCsr to DER. IdCsr is likely malformed".to_string())))}
            }
        ) {
            Ok(_) => (),
            Err(_) => {
                log::warn!(
                    "[IdCsr::validate()] {ERR_MSG_SIGNATURE_MISMATCH}");
                return Err(ConstraintError::Malformed(Some(ERR_MSG_SIGNATURE_MISMATCH.to_string())))}
        };
        Ok(())
    }
}

impl<S: Signature, P: PublicKey<S>> Constrained for IdCert<S, P> {
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        log::trace!("[IdCert::validate()] validating inner IdCertTbs with target {target:?}",);
        self.id_cert_tbs.validate(target)?;
        Ok(())
    }
}

impl<S: Signature, P: PublicKey<S>> Constrained for IdCertTbs<S, P> {
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        log::trace!(
            "Validating if DER encoding is intact for certificate serial {}",
            self.serial_number
        );
        match self.clone().to_der() {
            Ok(der) => der,
            Err(_) => {
                log::warn!("{}", crate::errors::ERR_CERTIFICATE_TO_DER_ERROR);
                return Err(ConstraintError::Malformed(Some(
                    crate::errors::ERR_CERTIFICATE_TO_DER_ERROR.to_string(),
                )));
            }
        };
        log::trace!("validating capabilities for target: {target:?}");
        self.capabilities.validate(target)?;
        self.issuer.validate(Some(Target::HomeServer))?;
        self.subject.validate(target)?;
        self.serial_number.validate(target)?;
        log::trace!("Checking if domain components of issuer and subject are equal");
        log::trace!("Issuer: {}", self.issuer);
        log::trace!("Subject: {}", self.subject);
        match equal_domain_components(&self.issuer, &self.subject) {
            true => debug!("Domain components of issuer and subject are equal"),
            false => {
                warn!(
                    "{}\nIssuer: {}\nSubject: {}",
                    ERR_MSG_DC_MISMATCH_ISSUER_SUBJECT, &self.issuer, &self.subject
                );
                return Err(ConstraintError::Malformed(Some(format!(
                    "{}\nIssuer: {}\nSubject: {}",
                    ERR_MSG_DC_MISMATCH_ISSUER_SUBJECT, &self.issuer, &self.subject
                ))));
            }
        }
        if let Some(target) = target {
            match target {
                Target::Actor => {
                    if self.capabilities.basic_constraints.ca {
                        return Err(ConstraintError::Malformed(Some(
                            ERR_MSG_ACTOR_CANNOT_BE_CA.to_string(),
                        )));
                    }
                }
                Target::HomeServer => {
                    if !self.capabilities.basic_constraints.ca {
                        return Err(ConstraintError::Malformed(Some(
                            ERR_MSG_HOME_SERVER_MISSING_CA_ATTR.to_string(),
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}
