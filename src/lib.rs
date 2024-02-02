// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use signature::Signer;

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct IdCsr {
    pub pub_key: String,
    pub federation_id: FederationId,
    pub session_id: String,
    pub expiry: Option<u64>,
}

impl IdCsr {
    pub fn to_id_cert_tbs(&self, expiry: u64, serial: &str) -> IdCertTBS {
        IdCertTBS {
            pub_key: self.pub_key.clone(),
            federation_id: self.federation_id.clone(),
            session_id: self.session_id.clone(),
            expiry,
            serial: serial.to_string(),
        }
    }
}

impl From<IdCertTBS> for IdCsr {
    fn from(value: IdCertTBS) -> Self {
        IdCsr {
            pub_key: value.pub_key,
            federation_id: value.federation_id,
            session_id: value.session_id,
            expiry: Some(value.expiry),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct FederationId {
    pub actor_name: String,
    pub domain: String,
    pub tld: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct IdCert {
    pub pub_key: String,
    pub federation_id: FederationId,
    pub session_id: String,
    pub expiry: u64,
    pub serial: String,
    pub signature: Signature,
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct IdCertTBS {
    pub pub_key: String,
    pub federation_id: FederationId,
    pub session_id: String,
    pub expiry: u64,
    pub serial: String,
}

impl IdCertTBS {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.pub_key.as_bytes());
        bytes.extend_from_slice(self.federation_id.actor_name.as_bytes());
        bytes.extend_from_slice(self.federation_id.domain.as_bytes());
        bytes.extend_from_slice(self.federation_id.tld.as_bytes());
        bytes.extend_from_slice(self.session_id.as_bytes());
        bytes.extend_from_slice(&self.expiry.to_be_bytes());
        bytes.extend_from_slice(self.serial.as_bytes());
        bytes.to_vec()
    }

    pub fn sign(&self, private_key: impl Signer<Signature>) -> IdCert {
        let signature = private_key.sign(&self.to_bytes());
        IdCert {
            pub_key: self.pub_key.clone(),
            federation_id: self.federation_id.clone(),
            session_id: self.session_id.clone(),
            expiry: self.expiry,
            serial: self.serial.clone(),
            signature,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Signature {
    pub(crate) signature: String,
    pub algorithm: SignatureMode,
}

impl Signature {
    pub fn as_bytes(&self) -> &[u8] {
        self.signature.as_bytes()
    }

    pub fn as_str(&self) -> &str {
        &self.signature
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
#[repr(u8)]
pub enum SignatureMode {
    Single(SignatureAlgorithm),
    Hybrid(SignatureAlgorithm, SignatureAlgorithm),
}

impl Default for SignatureMode {
    fn default() -> Self {
        SignatureMode::Single(SignatureAlgorithm::ED25519)
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Default)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    ECDSA_SECP256R1_SHA256,
    ECDSA_SECP384R1_SHA384,
    ECDSA_SECP521R1_SHA512,
    #[default]
    ED25519,
    ED448,
    RSASSA_PKCS1_v_1_5_SHA256,
    RSASSA_PKCS1_v_1_5_SHA384,
    RSASSA_PKCS1_v_1_5_SHA512,
    RSASSA_PSS_SHA256,
    RSASSA_PSS_SHA384,
    RSASSA_PSS_SHA512,
    ECDSA_BRAINPOOLP256R1_SHA256,
    ECDSA_BRAINPOOLP384R1_SHA384,
    ECDSA_BRAINPOOLP512R1_SHA512,
    CRYSTALS_DILITHIUM2,
    CRYSTALS_DILITHIUM3,
    CRYSTALS_DILITHIUM5,
    CRYSTALS_DILITHIUM2_AES,
    CRYSTALS_DILITHIUM3_AES,
    CRYSTALS_DILITHIUM5_AES,
}
