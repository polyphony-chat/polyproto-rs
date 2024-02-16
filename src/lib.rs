// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

pub mod cert;
pub mod key;
pub mod signature;

use std::fmt::Debug;

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum TbsCertToIdCert {
    #[error("field 'subject_unique_id' was None. Expected: Some(der::asn1::BitString)")]
    SubjectUid,
    #[error("field 'extensions' was None. Expected: Some(x509_cert::ext::Extensions)")]
    Extensions,
    #[error("Supplied integer too long")]
    Signature(der::Error),
}

#[derive(Error, Debug, PartialEq)]
pub enum IdCertToTbsCert {
    #[error("Serial number could not be converted")]
    SerialNumber(der::Error),
}

// DOCUMENTME: Document above things
// DOCUMENTME: When converting a X509Cert into an ID-Cert, it should at least be documented that this
//             certificate is not necessarily trusted and that the claims presented in the certificate
//             need to be verified first.

#[cfg(test)]
mod test {
    use der::asn1::Uint;
    use x509_cert::certificate::Profile;
    use x509_cert::serial_number::SerialNumber;

    #[derive(Clone, PartialEq, Eq, Debug)]
    enum TestProfile {}

    impl Profile for TestProfile {}

    fn strip_leading_zeroes(bytes: &[u8]) -> &[u8] {
        if let Some(stripped) = bytes.strip_prefix(&[0u8]) {
            stripped
        } else {
            bytes
        }
    }

    #[test]
    fn test_convert_serial_number() {
        let biguint = Uint::new(&[10u8, 240u8]).unwrap();
        assert_eq!(biguint.as_bytes(), &[10u8, 240u8]);
        let serial_number: SerialNumber<TestProfile> =
            SerialNumber::new(biguint.as_bytes()).unwrap();
        assert_eq!(
            strip_leading_zeroes(serial_number.as_bytes()),
            biguint.as_bytes()
        );

        let biguint = Uint::new(&[240u8, 10u8]).unwrap();
        assert_eq!(biguint.as_bytes(), &[240u8, 10u8]);
        let serial_number: SerialNumber<TestProfile> =
            SerialNumber::new(biguint.as_bytes()).unwrap();
        assert_eq!(
            strip_leading_zeroes(serial_number.as_bytes()),
            biguint.as_bytes()
        );
    }
}
