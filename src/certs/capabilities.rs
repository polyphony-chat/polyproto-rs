// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
/// Capabilities which an ID-Cert or ID-CSR might have. For ID-Certs, you'd find these capabilities
/// in the `Extensions` field of a certificate. ID-CSRs store these capabilities as part of the
/// `Attributes` field.
///
/// This struct only covers the CertCapability subtype trees of which at least one of the subtypes
/// are relevant to polyproto certificates.
pub struct Capabilities {
    /// The key usage extension defines the purpose of the key contained in the certificate.
    pub key_usage: Vec<KeyUsage>,
    /// Extension type that defines whether a given certificate is allowed
    /// to sign additional certificates and what path length restrictions may exist.
    pub basic_constraints: Vec<BasicConstraints>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// The key usage extension defines the purpose of the key contained in the certificate. The usage
/// restriction might be employed when a key that could be used for more than one operation is to
/// be restricted. See <https://cryptography.io/en/latest/x509/reference/#cryptography.x509.KeyUsage>
pub enum KeyUsage {
    /// This purpose is set to true when the subject public key is used for verifying digital
    /// signatures, other than signatures on certificates (`key_cert_sign`) and CRLs (`crl_sign`).
    DigitalSignature(bool),
    /// This purpose is set to true when the subject public key is used for verifying signatures on
    /// certificate revocation lists.
    CrlSign(bool),
    /// This purpose is set to true when the subject public key is used for verifying digital
    /// signatures, other than signatures on certificates (`key_cert_sign`) and CRLs (`crl_sign`).
    /// It is used to provide a non-repudiation service that protects against the signing entity
    /// falsely denying some action. In the case of later conflict, a reliable third party may
    /// determine the authenticity of the signed data. This was called `non_repudiation` in older
    /// revisions of the X.509 specification.
    ContentCommitment(bool),
    /// This purpose is set to true when the subject public key is used for enciphering private or
    /// secret keys.
    KeyEncipherment(bool),
    /// This purpose is set to true when the subject public key is used for directly enciphering raw
    /// user data without the use of an intermediate symmetric cipher.
    DataEncipherment(bool),
    /// This purpose is set to true when the subject public key is used for key agreement. For
    /// example, when a Diffie-Hellman key is to be used for key management, then this purpose is
    /// set to true.
    KeyAgreement(bool),
    /// This purpose is set to true when the subject public key is used for verifying signatures on
    /// public key certificates. If this purpose is set to true then ca must be true in the
    /// `BasicConstraints` extension.
    KeyCertSign(bool),
    /// When this purposes is set to true and the `key_agreement` purpose is also set, the subject
    /// public key may be used only for enciphering data while performing key agreement. The
    /// `KeyAgreement` capability must be set to `true` for this.
    EncipherOnly(bool),
    /// When this purposes is set to true and the `key_agreement` purpose is also set, the subject
    /// public key may be used only for deciphering data while performing key agreement. The
    /// `KeyAgreement` capability must be set to `true` for this.
    DecipherOnly(bool),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Basic constraints is an X.509 extension type that defines whether a given certificate is allowed
/// to sign additional certificates and what path length restrictions may exist.
pub enum BasicConstraints {
    /// Whether the certificate can sign certificates.
    Ca(bool),
    /// The maximum path length for certificates subordinate to this certificate. This attribute
    /// only has meaning if `ca` is true. If `ca` is true then a path length of None means there’s no
    /// restriction on the number of subordinate CAs in the certificate chain. If it is zero or
    /// greater then it defines the maximum length for a subordinate CA’s certificate chain. For
    /// example, a `path_length` of 1 means the certificate can sign a subordinate CA, but the
    /// subordinate CA is not allowed to create subordinates with `ca` set to true.
    PathLength(Option<u64>),
}
