// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Example implementation of polyproto's signature and key traits for ed25519-dalek.
// This example is not complete and should not be copy-pasted into a production environment without
// further scrutiny and consideration.

use std::str::FromStr;

use der::asn1::BitString;
use ed25519_dalek::{Signature as Ed25519DalekSignature, Signer, SigningKey, VerifyingKey};
use polyproto::certs::PublicKeyInfo;
use polyproto::key::{PrivateKey, PublicKey};
use polyproto::signature::Signature;
use rand::rngs::OsRng;
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SignatureBitStringEncoding};

fn main() {
    let mut csprng = rand::rngs::OsRng;
    // Generate a key pair
    let priv_key = Ed25519PrivateKey::gen_keypair(&mut csprng);
    println!("Private Key is: {:?}", priv_key.key.to_bytes());
    println!("Public Key is: {:?}", priv_key.public_key.key.to_bytes());
    println!(
        "Public Key OID is: {:?}",
        priv_key.public_key.algorithm_identifier()
    );
    println!();

    // Create and sign a message
    let message_unsigned = "hi my name is flori".as_bytes();
    let signature = priv_key.sign(message_unsigned);
    println!(
        "Signature of the message \"{}\": {:?}",
        String::from_utf8_lossy(message_unsigned),
        signature.as_signature().to_bytes()
    );

    // Verify the signature
    println!(
        "Is the signature valid? {}",
        priv_key
            .public_key
            .verify_signature(&signature, message_unsigned)
            .is_ok()
    );

    // Try to verify the same signature with different data, which should fail
    println!(
        "Trying again with different data. The result is: {}",
        priv_key
            .pubkey()
            .verify_signature(
                &signature,
                format!("{} ", String::from_utf8_lossy(message_unsigned)).as_bytes()
            )
            .is_ok()
    )
}

// As mentioned in the README, we start by implementing the signature trait.

// Here, we start by defining the signature type, which is a wrapper around the signature type from
// the ed25519-dalek crate.
#[derive(Debug, PartialEq, Eq, Clone)]
struct Ed25519Signature {
    signature: Ed25519DalekSignature,
    algorithm: AlgorithmIdentifierOwned,
}

impl std::fmt::Display for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.signature)
    }
}

// We implement the Signature trait for our signature type.
impl Signature for Ed25519Signature {
    // We define the signature type from the ed25519-dalek crate as the associated type.
    type Signature = Ed25519DalekSignature;

    fn as_bytes(&self) -> Vec<u8> {
        self.as_signature().to_vec()
    }

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

    #[cfg(not(tarpaulin_include))]
    fn from_bytes(signature: &[u8]) -> Self {
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
    #[cfg(not(tarpaulin_include))]
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
    // Verifies a signature. We use the `verify_strict` method from the ed25519-dalek crate.
    // This method is used to mitigate weak key forgery.
    fn verify_signature(
        &self,
        signature: &Ed25519Signature,
        data: &[u8],
    ) -> Result<(), polyproto::errors::composite::PublicKeyError> {
        match self.key.verify_strict(data, signature.as_signature()) {
            Ok(_) => Ok(()),
            Err(_) => Err(polyproto::errors::composite::PublicKeyError::BadSignature),
        }
    }

    // Returns the public key info. Public key info is used to encode the public key in a
    // certificate or a CSR. It is named after the `SubjectPublicKeyInfo` type from the X.509
    // standard, and thus includes the information needed to encode the public key in a certificate
    // or a CSR.
    #[cfg(not(tarpaulin_include))]
    fn public_key_info(&self) -> PublicKeyInfo {
        PublicKeyInfo {
            algorithm: Ed25519Signature::algorithm_identifier(),
            public_key_bitstring: BitString::from_bytes(&self.key.to_bytes()).unwrap(),
        }
    }

    #[cfg(not(tarpaulin_include))]
    fn try_from_public_key_info(
        public_key_info: PublicKeyInfo,
    ) -> Result<Self, polyproto::errors::composite::CertificateConversionError> {
        let mut key_vec = public_key_info.public_key_bitstring.raw_bytes().to_vec();
        key_vec.resize(32, 0);
        let signature_array: [u8; 32] = {
            let mut array = [0; 32];
            array.copy_from_slice(&key_vec[..]);
            array
        };
        Ok(Self {
            key: VerifyingKey::from_bytes(&signature_array).unwrap(),
        })
    }
}

#[test]
fn test_example() {
    main()
}
