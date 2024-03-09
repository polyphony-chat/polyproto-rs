// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::asn1::{BitString, Ia5String};
use der::Encode;
use ed25519_dalek::{Signature as Ed25519DalekSignature, Signer, SigningKey, VerifyingKey};
use polyproto::certs::PublicKeyInfo;
use polyproto::key::{PrivateKey, PublicKey};
use polyproto::signature::Signature;
use rand::rngs::OsRng;
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SignatureBitStringEncoding};
use thiserror::Error;
use x509_cert::attr::Attributes;
use x509_cert::name::RdnSequence;
use x509_cert::request::CertReq;

/// The following example uses the same setup as in ed25519_basic.rs, but in its main method, it
/// creates a certificate signing request (CSR) and writes it to a file. The CSR is created from a
/// polyproto ID CSR, which is a wrapper around a PKCS #10 CSR.
///
/// If you have openssl installed, you can inspect the CSR by running:
///
/// ```sh
/// openssl req -in cert.csr -verify
/// ```

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn main() {
    let mut csprng = rand::rngs::OsRng;
    let priv_key = Ed25519PrivateKey::gen_keypair(&mut csprng);
    println!("Private Key is: {:?}", priv_key.key.to_bytes());
    println!("Public Key is: {:?}", priv_key.public_key.key.to_bytes());
    println!();

    let _csr = polyproto::certs::idcsr::IdCsr::new(
        &RdnSequence::from_str("CN=flori,DC=www,DC=polyphony,DC=chat,UID=flori@polyphony.chat,uniqueIdentifier=client1").unwrap(),
        &priv_key,
        &Attributes::new(),
    )
    .unwrap();

    let certrequest = CertReq::from(_csr.try_into().unwrap());
    println!("Certrequest der bytes: {:?}", certrequest.to_der().unwrap());
    let data = certrequest.to_der().unwrap();
    let file_name_with_extension = "cert.csr";
    #[cfg(not(target_arch = "wasm32"))]
    std::fs::write(file_name_with_extension, &data).unwrap();
}

// As mentioned in the README, we start by implementing the signature trait.

// Here, we start by defining the signature type, which is a wrapper around the signature type from
// the ed25519-dalek crate.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Ed25519Signature {
    signature: Ed25519DalekSignature,
    algorithm: AlgorithmIdentifierOwned,
}

// We implement the Signature trait for our signature type.
impl Signature for Ed25519Signature {
    // We define the signature type from the ed25519-dalek crate as the associated type.
    type Signature = Ed25519DalekSignature;

    // This is straightforward: we return a reference to the signature.
    fn as_signature(&self) -> &Self::Signature {
        &self.signature
    }

    // The algorithm identifier for a given signature implementation is constant. We just need
    // to define it here.
    fn algorithm_identifier() -> AlgorithmIdentifierOwned {
        AlgorithmIdentifierOwned {
            // This is the OID for Ed25519. It is defined in the IANA registry.
            oid: ObjectIdentifier::from_str("1.3.101.112").unwrap(),
            // For this example, we don't need or want any parameters.
            parameters: None,
        }
    }

    fn from_bitstring(signature: &[u8]) -> Self {
        let mut signature_vec = signature.to_vec();
        signature_vec.resize(64, 0);
        let signature_array: [u8; 64] = {
            let mut array = [0; 64];
            array.copy_from_slice(&signature_vec[..]);
            array
        };
        Self {
            signature: Ed25519DalekSignature::from_bytes(&signature_array),
            algorithm: Self::algorithm_identifier(),
        }
    }
}

// The `SignatureBitStringEncoding` trait is used to convert a signature to a bit string. We implement
// it for our signature type.
impl SignatureBitStringEncoding for Ed25519Signature {
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        BitString::from_bytes(&self.as_signature().to_bytes())
    }
}

// Next, we implement the key traits. We start by defining the private key type.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ed25519PrivateKey {
    // Defined below
    public_key: Ed25519PublicKey,
    // The private key from the ed25519-dalek crate
    key: SigningKey,
}

impl PrivateKey<Ed25519Signature> for Ed25519PrivateKey {
    type PublicKey = Ed25519PublicKey;

    // Return a reference to the public key
    fn pubkey(&self) -> &Self::PublicKey {
        &self.public_key
    }

    // Signs a message. The beauty of having to wrap the ed25519-dalek crate is that we can
    // harness all of its functionality, such as the `sign` method.
    fn sign(&self, data: &[u8]) -> Ed25519Signature {
        let signature = self.key.sign(data);
        Ed25519Signature {
            signature,
            algorithm: self.algorithm_identifier(),
        }
    }
}

impl Ed25519PrivateKey {
    // Let's also define a handy method to generate a key pair.
    pub fn gen_keypair(csprng: &mut OsRng) -> Self {
        let key = SigningKey::generate(csprng);
        let public_key = Ed25519PublicKey {
            key: key.verifying_key(),
        };
        Self { public_key, key }
    }
}

// Same thing as above for the public key type.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ed25519PublicKey {
    // The public key type from the ed25519-dalek crate
    key: VerifyingKey,
}

impl PublicKey<Ed25519Signature> for Ed25519PublicKey {
    // We have to define an error type. The error type is used to signal that the signature
    // verification failed. We define it as a simple enum using the `thiserror` crate.
    type Error = Error;

    // Verifies a signature. We use the `verify_strict` method from the ed25519-dalek crate.
    // This method is used to mitigate weak key forgery.
    fn verify_signature(
        &self,
        signature: &Ed25519Signature,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        match self.key.verify_strict(data, signature.as_signature()) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::SignatureVerification),
        }
    }

    // Returns the public key info. Public key info is used to encode the public key in a
    // certificate or a CSR. It is named after the `SubjectPublicKeyInfo` type from the X.509
    // standard, and thus includes the information needed to encode the public key in a certificate
    // or a CSR.
    fn public_key_info(&self) -> PublicKeyInfo {
        PublicKeyInfo {
            algorithm: Ed25519Signature::algorithm_identifier(),
            public_key_bitstring: BitString::from_bytes(&self.key.to_bytes()).unwrap(),
        }
    }
}

#[derive(Error, Debug, Clone)]
enum Error {
    #[error("The signature failed to verify")]
    SignatureVerification,
}
