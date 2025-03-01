// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::str::FromStr;
use std::time::Duration;

use der::asn1::{BitString, Uint, UtcTime};
use ed25519_dalek::ed25519::signature::Signer;
use ed25519_dalek::{Signature as Ed25519DalekSignature, SigningKey, VerifyingKey};
use log::{debug, LevelFilter};
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Logger, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::Filter;
use polyproto::certs::capabilities::Capabilities;
use polyproto::certs::idcert::IdCert;
use polyproto::certs::idcsr::IdCsr;
use polyproto::certs::PublicKeyInfo;
use polyproto::errors::composite::ConversionError;
use polyproto::key::{PrivateKey, PublicKey};
use polyproto::signature::Signature;
use polyproto::Name;
use rand::rngs::OsRng;
use spki::{AlgorithmIdentifierOwned, ObjectIdentifier, SignatureBitStringEncoding};
use x509_cert::time::{Time, Validity};

#[derive(Debug)]
struct LogFilter;

impl Filter for LogFilter {
    fn filter(&self, record: &log::Record) -> log4rs::filter::Response {
        if record.target().starts_with("polyproto") {
            log4rs::filter::Response::Accept
        } else {
            log4rs::filter::Response::Reject
        }
    }
}

pub(crate) fn init_logger() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "trace");
    }
    let log_target_stdout = ConsoleAppender::builder()
        .target(log4rs::append::console::Target::Stdout)
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)} | {h({l:<6.6})} | {t:<35} | {m}{n}",
        )))
        .build();
    let loglevel = match std::env::var("RUST_LOG")
        .unwrap_or("trace".to_string())
        .to_lowercase()
        .as_str()
    {
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        x => {
            eprintln!("Found RUST_LOG variable to be {x}. Valid values are 'info', 'debug', 'trace'. Defaulting to 'trace'.");
            LevelFilter::Trace
        }
    };
    let log_config = log4rs::Config::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(LogFilter))
                .build("stdout", Box::new(log_target_stdout)),
        )
        .logger(
            Logger::builder()
                .appender("stdout")
                .build("polyproto", loglevel),
        )
        .build(Root::builder().appender("stdout").build(loglevel))
        .map_err(|e| Box::new(e) as Box<dyn std::fmt::Debug>)
        .unwrap();

    let _handle = log4rs::init_config(log_config);
    let _ = _handle
        .expect("`cargo test` is unsupported - Use `cargo nextest` instead by installing nextest.");
}

pub fn actor_subject(cn: &str) -> Name {
    Name::from_str(&format!(
        "CN={},DC=polyphony,DC=chat,UID={}@polyphony.chat,uniqueIdentifier=client1",
        cn, cn
    ))
    .unwrap()
}

pub fn default_validity() -> Validity {
    Validity {
        not_before: Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(10)).unwrap()),
        not_after: Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(1000)).unwrap()),
    }
}

pub fn home_server_subject() -> Name {
    Name::from_str("DC=polyphony,DC=chat").unwrap()
}

pub fn gen_priv_key() -> Ed25519PrivateKey {
    Ed25519PrivateKey::gen_keypair(&mut rand::rngs::OsRng)
}

pub fn actor_id_cert(cn: &str) -> IdCert<Ed25519Signature, Ed25519PublicKey> {
    let priv_key = gen_priv_key();
    IdCert::from_actor_csr(
        actor_csr(cn, &priv_key),
        &priv_key,
        Uint::new(&[8]).unwrap(),
        home_server_subject(),
        default_validity(),
    )
    .unwrap()
}

pub fn actor_csr(
    cn: &str,
    priv_key: &Ed25519PrivateKey,
) -> IdCsr<Ed25519Signature, Ed25519PublicKey> {
    IdCsr::new(
        &actor_subject(cn),
        priv_key,
        &Capabilities::default_actor(),
        Some(polyproto::certs::Target::Actor),
    )
    .unwrap()
}

pub fn home_server_id_cert() -> IdCert<Ed25519Signature, Ed25519PublicKey> {
    let priv_key = gen_priv_key();
    IdCert::from_ca_csr(
        home_server_csr(&priv_key),
        &priv_key,
        Uint::new(&[8]).unwrap(),
        home_server_subject(),
        default_validity(),
    )
    .unwrap()
}

pub fn home_server_csr(priv_key: &Ed25519PrivateKey) -> IdCsr<Ed25519Signature, Ed25519PublicKey> {
    IdCsr::new(
        &home_server_subject(),
        priv_key,
        &Capabilities::default_home_server(),
        Some(polyproto::certs::Target::HomeServer),
    )
    .unwrap()
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) struct Ed25519Signature {
    pub(crate) signature: Ed25519DalekSignature,
    pub(crate) algorithm: AlgorithmIdentifierOwned,
}

impl std::fmt::Display for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.as_signature())
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

    fn as_bytes(&self) -> Vec<u8> {
        self.as_signature().to_vec()
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
            Err(e) => {
                debug!("{e}");
                Err(polyproto::errors::composite::PublicKeyError::BadSignature)
            }
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
