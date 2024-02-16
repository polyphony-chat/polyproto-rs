// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::asn1::{BitString, Uint};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::certificate::{Profile, TbsCertificateInner};
use x509_cert::ext::Extensions;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

use crate::signature::{Signature, SignatureAlgorithm};
use crate::{IdCertToTbsCert, TbsCertToIdCert};

pub struct IdCert<S: Signature, T: SignatureAlgorithm> {
    pub tbs_certificate: IdCertTbs<T>,
    pub signature: S,
}

pub struct IdCertTbs<T: SignatureAlgorithm> {
    pub serial_number: Uint,
    pub signature_algorithm: T,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo<T>,
    pub subject_unique_id: BitString,
    pub extensions: Extensions,
}

pub struct SubjectPublicKeyInfo<T: SignatureAlgorithm> {
    pub algorithm: T,
    pub subject_public_key: BitString,
}

impl<T: SignatureAlgorithm> From<SubjectPublicKeyInfoOwned> for SubjectPublicKeyInfo<T> {
    fn from(value: SubjectPublicKeyInfoOwned) -> Self {
        SubjectPublicKeyInfo {
            algorithm: value.algorithm.into(),
            subject_public_key: value.subject_public_key,
        }
    }
}

impl<T: SignatureAlgorithm> From<SubjectPublicKeyInfo<T>> for SubjectPublicKeyInfoOwned {
    fn from(value: SubjectPublicKeyInfo<T>) -> Self {
        let algorithm = AlgorithmIdentifierOwned {
            oid: value.algorithm.oid(),
            parameters: value.algorithm.parameters(),
        };

        SubjectPublicKeyInfoOwned {
            algorithm,
            subject_public_key: value.subject_public_key,
        }
    }
}

impl<T: SignatureAlgorithm, P: Profile> TryFrom<TbsCertificateInner<P>> for IdCertTbs<T> {
    type Error = TbsCertToIdCert;

    fn try_from(value: TbsCertificateInner<P>) -> Result<Self, Self::Error> {
        let subject_unique_id = match value.subject_unique_id {
            Some(suid) => suid,
            None => return Err(TbsCertToIdCert::SubjectUid),
        };

        let extensions = match value.extensions {
            Some(ext) => ext,
            None => return Err(TbsCertToIdCert::Extensions),
        };

        let subject_public_key_info =
            SubjectPublicKeyInfo::<T>::from(value.subject_public_key_info);

        let serial_number = match Uint::new(value.serial_number.as_bytes()) {
            Ok(snum) => snum,
            Err(e) => return Err(TbsCertToIdCert::Signature(e)),
        };

        Ok(IdCertTbs {
            serial_number,
            signature_algorithm: value.signature.into(),
            issuer: value.issuer,
            validity: value.validity,
            subject: value.subject,
            subject_public_key_info,
            subject_unique_id,
            extensions,
        })
    }
}

impl<T: SignatureAlgorithm, P: Profile> TryFrom<IdCertTbs<T>> for TbsCertificateInner<P> {
    type Error = IdCertToTbsCert;

    fn try_from(value: IdCertTbs<T>) -> Result<Self, Self::Error> {
        let serial_number = match SerialNumber::<P>::new(value.serial_number.as_bytes()) {
            Ok(sernum) => sernum,
            Err(e) => return Err(IdCertToTbsCert::SerialNumber(e)),
        };

        let signature = AlgorithmIdentifierOwned {
            oid: value.signature_algorithm.oid(),
            parameters: value.signature_algorithm.parameters(),
        };

        Ok(TbsCertificateInner {
            version: x509_cert::Version::V3,
            serial_number,
            signature,
            issuer: value.issuer,
            validity: value.validity,
            subject: value.subject,
            subject_public_key_info: value.subject_public_key_info.into(),
            issuer_unique_id: None,
            subject_unique_id: Some(value.subject_unique_id),
            extensions: Some(value.extensions),
        })
    }
}
