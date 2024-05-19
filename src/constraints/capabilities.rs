// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::errors::{ERR_MSG_ACTOR_MISSING_SIGNING_CAPS, ERR_MSG_HOME_SERVER_MISSING_CA_ATTR};

use super::*;

impl Constrained for Capabilities {
    fn validate(&self, _target: Option<Target>) -> Result<(), ConstraintError> {
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
                ERR_MSG_ACTOR_MISSING_SIGNING_CAPS.to_string(),
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
                return Err(ConstraintError::Malformed(Some(format!(
                    "{} Missing capability \"KeyCertSign\"",
                    ERR_MSG_HOME_SERVER_MISSING_CA_ATTR
                ))));
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
