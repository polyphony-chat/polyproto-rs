// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::str::FromStr;

use der::asn1::BitString;
use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature as Ed25519DalekSignature, SigningKey, VerifyingKey};
use httptest::matchers::request;
use httptest::responders::json_encoded;
use httptest::{Expectation, Server};
use polyproto::api::core::current_unix_time;
use polyproto::api::HttpClient;
use polyproto::certs::PublicKeyInfo;
use polyproto::errors::composite::ConversionError;
use polyproto::key::{PrivateKey, PublicKey};
use polyproto::signature::Signature;
use polyproto::types::routes::core::v1::GET_CHALLENGE_STRING;
use serde_json::json;
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SignatureBitStringEncoding};
use url::Url;

async fn setup_example() -> Server {
    let server = Server::run();
    server.expect(
        Expectation::matching(request::method_path(
            GET_CHALLENGE_STRING.method.as_str(),
            GET_CHALLENGE_STRING.path,
        ))
        .respond_with(json_encoded(json!({
            "challenge": "abcd".repeat(8),
            "expires": current_unix_time() + 100
        }))),
    );
    server
}

#[tokio::main]
async fn main() {
    let server = setup_example().await;
    let url = format!("http://{}", server.addr());

    // The actual example starts here.
    // Create a new HTTP client
    let client = HttpClient::new().unwrap();
    // Create an authorized session
    let session: polyproto::api::Session<Ed25519Signature, Ed25519PrivateKey> =
        polyproto::api::Session::new(&client, "12345", Url::parse(&url).unwrap(), None);
    // You can now use the client to make requests to the polyproto home server!
    // Routes are documented under <https://docs.polyphony.chat/APIs/core/>, and each route has a
    // corresponding method in the `HttpClient` struct. For example, if we wanted to get a challenge
    // string from the server, we would call:
    let challenge = session.get_challenge_string().await.unwrap();
    println!("Challenge string: {}", challenge.challenge());
    println!(
        "Challenge expires at UNIX timestamp: {}",
        challenge.expires()
    );
}

#[test]
fn test_example() {
    main()
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Ed25519Signature {
    pub(crate) signature: Ed25519DalekSignature,
    pub(crate) algorithm: AlgorithmIdentifierOwned,
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
    fn to_bitstring(&self) -> der::Result<der::asn1::BitString> {
        BitString::from_bytes(&self.as_signature().to_bytes())
    }
}

// Next, we implement the key traits. We start by defining the private key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ed25519PrivateKey {
    // Defined below
    pub(crate) public_key: Ed25519PublicKey,
    // The private key from the ed25519-dalek crate
    pub(crate) key: SigningKey,
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

// Same thing as above for the public key type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ed25519PublicKey {
    // The public key type from the ed25519-dalek crate
    pub(crate) key: VerifyingKey,
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
    fn public_key_info(&self) -> PublicKeyInfo {
        PublicKeyInfo {
            algorithm: Ed25519Signature::algorithm_identifier(),
            public_key_bitstring: BitString::from_bytes(&self.key.to_bytes()).unwrap(),
        }
    }

    fn try_from_public_key_info(public_key_info: PublicKeyInfo) -> Result<Self, ConversionError> {
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
