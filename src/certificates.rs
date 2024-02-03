// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use signature::Signer;

use crate::{HasSignatureType, SignatureType};

/// A certificate signing request (CSR) for a polyproto identity certificate.
/// `expiry` is an optional field that specifies the expiry UNIX timestamp of the requested certificate.
/// The certificate authority can choose to ignore this field and issue a certificate with a different expiry.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct IdCsr {
    pub pub_key: String,
    pub pub_key_algorithm: SignatureType,
    pub federation_id: FederationId,
    pub session_id: String,
    pub expiry: Option<u64>,
}

impl IdCsr {
    /// Makes a new [`IdCertTBS`] from the given [`IdCsr`] by adding information about the
    /// certificate's serial number and expiry UNIX timestamp.
    pub fn to_id_cert_tbs(&self, expiry: u64, serial: &str) -> IdCertTBS {
        IdCertTBS {
            pub_key: self.pub_key.clone(),
            pub_key_algorithm: self.pub_key_algorithm,
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
            pub_key_algorithm: value.pub_key_algorithm,
            federation_id: value.federation_id,
            session_id: value.session_id,
            expiry: Some(value.expiry),
        }
    }
}

/// A unique identifier for actors in the polyproto federation model, consisting of an actor name,
/// domain, and top-level domain (TLD).
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct FederationId {
    pub actor_name: String,
    pub domain: String,
    pub tld: String,
}

/// A signed identity certificate for a polyproto actor, signed by a certificate authority.
/// The certificate authority is represented by the `domain` and `tld` fields of the [`federation_id`](FederationId).
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct IdCert {
    pub pub_key: String,
    pub pub_key_algorithm: SignatureType,
    pub federation_id: FederationId,
    pub session_id: String,
    pub expiry: u64,
    pub serial: String,
    pub signature: Signature<SignatureType>,
}

/// A signature for a certificate, consisting of a signature type and the signature string itself.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Signature<T: Copy> {
    pub signature_type: T,
    pub signature: String,
}

/// An unsigned certificate to-be-signed (TBS) for a polyproto actor, containing an expiry UNIX
/// timestamp and a unique serial number in addition to the information supplied in a [`IdCsr`].
///
/// A signing authority can sign this TBS to produce a [`IdCert`]. Signing authorities must verify
/// all information in the TBS to ensure that the certificate is valid and up to the polyproto
/// specification's standards.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct IdCertTBS {
    pub pub_key: String,
    pub pub_key_algorithm: SignatureType,
    pub federation_id: FederationId,
    pub session_id: String,
    pub expiry: u64,
    pub serial: String,
}

impl IdCertTBS {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&self.pub_key.len().to_be_bytes());
        bytes.extend_from_slice(self.pub_key.as_bytes());
        bytes.extend_from_slice(&self.federation_id.actor_name.len().to_be_bytes());
        bytes.extend_from_slice(self.federation_id.actor_name.as_bytes());
        bytes.extend_from_slice(&self.federation_id.domain.len().to_be_bytes());
        bytes.extend_from_slice(self.federation_id.domain.as_bytes());
        bytes.extend_from_slice(&self.federation_id.tld.len().to_be_bytes());
        bytes.extend_from_slice(self.federation_id.tld.as_bytes());
        bytes.extend_from_slice(&self.session_id.len().to_be_bytes());
        bytes.extend_from_slice(self.session_id.as_bytes());
        bytes.extend_from_slice(&self.expiry.to_be_bytes());
        bytes.extend_from_slice(&self.serial.len().to_be_bytes());
        bytes.extend_from_slice(self.serial.as_bytes());
        bytes
    }

    pub fn try_sign<P: Signer<Signature<SignatureType>> + HasSignatureType>(
        self,
        private_key: &P,
    ) -> Result<IdCert, crate::error::Error> {
        if private_key.signature_type() != self.pub_key_algorithm {
            Err(crate::error::Error::SignatureTypeMismatch(
                private_key.signature_type(),
                self.pub_key_algorithm,
            ))?
        }
        let signature = private_key.sign(&self.to_bytes());
        Ok(IdCert {
            pub_key: self.pub_key,
            pub_key_algorithm: self.pub_key_algorithm,
            federation_id: self.federation_id,
            session_id: self.session_id,
            expiry: self.expiry,
            serial: self.serial,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use signature::Signer;

    use crate::{HasSignatureType, SignatureType};

    use super::{IdCsr, Signature};

    struct MyKey {
        _key: String,
        _algorithm: SignatureType,
    }

    impl Signer<Signature<SignatureType>> for MyKey {
        fn try_sign(&self, msg: &[u8]) -> Result<Signature<SignatureType>, signature::Error> {
            let mut str = String::from_utf8_lossy(msg).to_string();
            str += " signed";
            Ok(Signature {
                signature_type: SignatureType::Single(crate::SignatureAlgorithm::ED25519),
                signature: str,
            })
        }
    }

    impl HasSignatureType for MyKey {
        fn signature_type(&self) -> SignatureType {
            self._algorithm
        }
    }

    #[test]
    fn naive_signing_test() {
        let msg = "my message,".as_bytes();
        let key = MyKey {
            _key: "a key".to_string(),
            _algorithm: SignatureType::Single(crate::SignatureAlgorithm::ED25519),
        };
        assert_eq!(
            key.sign(msg),
            Signature {
                signature_type: SignatureType::Single(crate::SignatureAlgorithm::ED25519),
                signature: "my message, signed".to_string()
            }
        )
    }

    #[test]
    fn naive_cert_sign() {
        let private_key = MyKey {
            _key: "a key".to_string(),
            _algorithm: SignatureType::Single(crate::SignatureAlgorithm::ED25519),
        };
        let csr = IdCsr {
            pub_key: "my_key".to_string(),
            pub_key_algorithm: SignatureType::Single(crate::SignatureAlgorithm::ED25519),
            federation_id: super::FederationId {
                actor_name: "xenia".to_string(),
                domain: "transperson".to_string(),
                tld: "rocks".to_string(),
            },
            session_id: "34898945754789sdfa".to_string(),
            expiry: None,
        };

        let cert_tbs = csr.to_id_cert_tbs(123890890, "0983hf45yncwe84");
        assert!(cert_tbs.clone().try_sign(&private_key).is_ok());
        let cert = cert_tbs.try_sign(&private_key).unwrap();
        assert_eq!(
            cert.signature.signature_type,
            SignatureType::Single(crate::SignatureAlgorithm::ED25519)
        );
        assert!(cert.signature.signature.contains("signed"));
    }

    #[test]
    fn mismatched_key_types() {
        let private_key = MyKey {
            _key: "a key".to_string(),
            _algorithm: SignatureType::Single(crate::SignatureAlgorithm::ECDSA_SECP256R1_SHA256),
        };
        let csr = IdCsr {
            pub_key: "mykey".to_string(),
            pub_key_algorithm: SignatureType::Single(
                crate::SignatureAlgorithm::CRYSTALS_DILITHIUM2,
            ),
            federation_id: super::FederationId {
                actor_name: "xenia".to_string(),
                domain: "transperson".to_string(),
                tld: "rocks".to_string(),
            },
            session_id: "34898945754789sdfa".to_string(),
            expiry: None,
        };

        let cert_tbs = csr.to_id_cert_tbs(123890890, "0983hf45yncwe84");
        assert!(cert_tbs.try_sign(&private_key).is_err());
    }
}
