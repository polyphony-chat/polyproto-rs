use signature::Signer;

pub struct IdCsr {
    pub pub_key: String,
    pub federation_id: FederationId,
    pub session_id: String,
    pub expiry: Option<u64>,
}

impl IdCsr {
    pub fn sign(&self, private_key: impl Signer<Signature>) -> IdCert {
        IdCert {
            pub_key: self.pub_key.clone(),
            federation_id: self.federation_id.clone(),
            session_id: self.session_id.clone(),
            expiry: self.expiry.unwrap_or(0b1),
            serial: String::from("wow"),
            signature: private_key.sign(todo!()),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct FederationId {
    pub actor_name: String,
    pub domain: String,
    pub tld: String,
}

#[derive(Clone)]
pub(crate) struct IdCertTBS {
    pub(crate) pub_key: String,
    pub(crate) federation_id: FederationId,
    pub(crate) session_id: String,
    pub(crate) expiry: u64,
    pub(crate) serial: String,
}

impl IdCertTBS {
    fn sign(&self, private_key: impl Signer<Signature>) -> IdCert {
        IdCert {
            pub_key: self.pub_key.clone(),
            federation_id: self.federation_id.clone(),
            session_id: self.session_id.clone(),
            expiry: self.expiry,
            serial: self.serial.clone(),
            signature: private_key.sign(&self.to_bytes()),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(self.pub_key.as_bytes());
        bytes.extend_from_slice(self.federation_id.actor_name.as_bytes());
        bytes.extend_from_slice(self.federation_id.domain.as_bytes());
        bytes.extend_from_slice(self.federation_id.tld.as_bytes());
        bytes.extend_from_slice(self.session_id.as_bytes());
        bytes.extend_from_slice(&self.expiry.to_be_bytes());
        bytes.extend_from_slice(self.serial.as_bytes());
        bytes
    }
}

pub struct IdCert {
    pub pub_key: String,
    pub federation_id: FederationId,
    pub session_id: String,
    pub expiry: u64,
    pub serial: String,
    pub signature: Signature,
}

#[allow(non_camel_case_types)]
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub enum Signature {
    ECDSA_SECP256R1_SHA256(String),
    ECDSA_SECP384R1_SHA384(String),
    ECDSA_SECP521R1_SHA512(String),
    ED25519(String),
    ED448(String),
}

impl Signature {
    pub fn as_string(&self) -> String {
        match self {
            Signature::ECDSA_SECP256R1_SHA256(s) => s.clone(),
            Signature::ECDSA_SECP384R1_SHA384(s) => s.clone(),
            Signature::ECDSA_SECP521R1_SHA512(s) => s.clone(),
            Signature::ED25519(s) => s.clone(),
            Signature::ED448(s) => s.clone(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.as_string().as_bytes()
    }
}
