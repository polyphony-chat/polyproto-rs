// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;

impl<S: Signature, P: PublicKey<S>> Constrained for IdCsrInner<S, P> {
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        self.capabilities.validate(target)?;
        self.subject.validate(target)?;
        if let Some(target) = target {
            match target {
                Target::Actor => {
                    if self.capabilities.basic_constraints.ca {
                        return Err(ConstraintError::Malformed(Some(
                            "Actor CSR must not be a CA".to_string(),
                        )));
                    }
                }
                Target::HomeServer => {
                    if !self.capabilities.basic_constraints.ca {
                        return Err(ConstraintError::Malformed(Some(
                            "Home server CSR must have the CA capability set to true".to_string(),
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
        self.inner_csr.validate(target)?;
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
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        self.id_cert_tbs.validate(target)?;
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
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError> {
        self.capabilities.validate(target)?;
        self.issuer.validate(target)?;
        self.subject.validate(target)?;
        match equal_domain_components(&self.issuer, &self.subject) {
            true => (),
            false => {
                return Err(ConstraintError::Malformed(Some(
                    "Domain components of issuer and subject are not equal".to_string(),
                )))
            }
        }
        if let Some(target) = target {
            match target {
                Target::Actor => {
                    if self.capabilities.basic_constraints.ca {
                        return Err(ConstraintError::Malformed(Some(
                            "Actor cert must not be a CA".to_string(),
                        )));
                    }
                }
                Target::HomeServer => {
                    if !self.capabilities.basic_constraints.ca {
                        return Err(ConstraintError::Malformed(Some(
                            "Home server cert must have the CA capability set to true".to_string(),
                        )));
                    }
                }
            }
        }
        Ok(())
    }
}
