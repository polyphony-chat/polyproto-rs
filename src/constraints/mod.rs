// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use der::Length;
use regex::Regex;
use x509_cert::name::{Name, RelativeDistinguishedName};

use crate::certs::capabilities::{Capabilities, KeyUsage};
use crate::certs::idcert::IdCert;
use crate::certs::idcerttbs::IdCertTbs;
use crate::certs::idcsr::{IdCsr, IdCsrInner};
use crate::certs::{equal_domain_components, SessionId, Target};
use crate::errors::ConstraintError;
use crate::key::PublicKey;
use crate::signature::Signature;
use crate::{
    Constrained, OID_RDN_COMMON_NAME, OID_RDN_DOMAIN_COMPONENT, OID_RDN_UID,
    OID_RDN_UNIQUE_IDENTIFIER,
};

pub mod capabilities;
pub mod certs;
pub mod name;
pub mod session_id;
#[cfg(feature = "types")]
pub mod types;

#[cfg(test)]
mod name_constraints {
    use std::str::FromStr;

    use x509_cert::name::Name;

    use crate::certs::Target;
    use crate::testing_utils::init_logger;
    use crate::Constrained;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn correct() {
        init_logger();
        let name = Name::from_str(
            "cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=h3g2jt4dhfgj8hjs",
        )
        .unwrap();
        let targets = [None, Some(Target::Actor)];
        for target in targets.into_iter() {
            name.validate(target).unwrap();
            let name = Name::from_str(
                "CN=flori,DC=polyphony,DC=chat,UID=flori@polyphony.chat,uniqueIdentifier=meow",
            )
            .unwrap();
            name.validate(target).unwrap();
            let name = Name::from_str(
                "cn=flori,dc=some,dc=domain,dc=that,dc=is,dc=quite,dc=long,dc=geez,dc=thats,dc=alotta,dc=subdomains,dc=example,dc=com,uid=flori@some.domain.that.is.quite.long.geez.thats.alotta.subdomains.example.com,uniqueIdentifier=h3g2jt4dhfgj8hjs",
            )
            .unwrap();
            name.validate(target).unwrap();
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn mismatch_uid_dcs() {
        init_logger();
        let targets = [None, Some(Target::Actor), Some(Target::HomeServer)];
        for target in targets.into_iter() {
            let name = Name::from_str(
                "cn=flori,dc=some,dc=domain,dc=that,dc=is,dc=quite,dc=long,dc=geez,dc=alotta,dc=subdomains,dc=example,dc=com,uid=flori@some.domain.that.is.quite.long.geez.thats.alotta.subdomains.example.com,uniqueIdentifier=h3g2jt4dhfgj8hjs",
            )
            .unwrap();
            name.validate(target).err().unwrap();

            let name = Name::from_str(
                "cn=flori,dc=some,dc=domain,dc=that,dc=is,dc=quite,dc=long,dc=geez,dc=alotta,dc=subdomains,dc=example,dc=com,uid=flori@domain.that.is.quite.long.geez.thats.alotta.subdomains.example.com,uniqueIdentifier=h3g2jt4dhfgj8hjs",
            )
            .unwrap();
            name.validate(target).err().unwrap();
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn no_domain_component() {
        init_logger();
        let targets = [None, Some(Target::Actor)];
        for target in targets.into_iter() {
            let name = Name::from_str("CN=flori").unwrap();
            assert!(name.validate(target).is_err());
            let name = Name::from_str("CN=flori,uid=flori@localhost").unwrap();
            assert!(name.validate(target).is_err());
            let name = Name::from_str("CN=flori,uniqueIdentifier=12345678901234567890123456789012")
                .unwrap();
            assert!(name.validate(target).is_err());
            let name = Name::from_str(
                "CN=flori,uid=flori@localhost,uniqueIdentifier=12345678901234567890123456789012",
            )
            .unwrap();
            assert!(name.validate(target).is_err());
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn two_cns() {
        init_logger();
        let targets = [None, Some(Target::Actor)];
        for target in targets.into_iter() {
            let name = Name::from_str("CN=flori,CN=xenia,DC=localhost").unwrap();
            assert!(name.validate(target).is_err());
            let name = Name::from_str("CN=flori,CN=xenia,uid=numbaone").unwrap();
            assert!(name.validate(target).is_err());
            let name = Name::from_str("CN=flori,CN=xenia,uniqueIdentifier=numbaone").unwrap();
            assert!(name.validate(target).is_err());
            let name =
                Name::from_str("CN=flori,CN=xenia,uid=numbaone,uniqueIdentifier=numbatwo").unwrap();
            assert!(name.validate(target).is_err());
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn two_uid_or_uniqueid() {
        init_logger();
        let targets = [None, Some(Target::Actor)];
        for target in targets.into_iter() {
            let name = Name::from_str("CN=flori,DC=localhost,uid=numbaone,uid=numbatwo").unwrap();
            assert!(name.validate(target).is_err());
            let name = Name::from_str(
                "CN=flori,DC=localhost,uniqueIdentifier=numbaone,uniqueIdentifier=numbatwo",
            )
            .unwrap();
            assert!(name.validate(target).is_err());
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn uid_and_no_uniqueid_or_uniqueid_and_no_uid() {
        init_logger();
        let targets = [None, Some(Target::Actor)];
        for target in targets.into_iter() {
            let name = Name::from_str("CN=flori,CN=xenia,uid=numbaone").unwrap();
            assert!(name.validate(target).is_err());
            let name = Name::from_str("CN=flori,CN=xenia,uniqueIdentifier=numbaone").unwrap();
            assert!(name.validate(target).is_err())
        }
    }
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn malformed_session_id_fails() {
        init_logger();
        let targets = [None, Some(Target::Actor)];
        for target in targets.into_iter() {
            let name =
                Name::from_str("cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=")
                    .unwrap();
            assert!(name.validate(target).is_err());
            let name =
            Name::from_str("cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=123456789012345678901234567890123").unwrap();
            assert!(name.validate(target).is_err());
            let name =
            Name::from_str("cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=变性人的生命和权利必须得到保护").unwrap();
            assert!(name.validate(target).is_err());
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn malformed_uid_fails() {
        init_logger();
        let targets = [None, Some(Target::Actor)];
        for target in targets.into_iter() {
            let name =
                Name::from_str("cn=flori,dc=localhost,uid=flori@,uniqueIdentifier=3245").unwrap();
            assert!(name.validate(target).is_err());
            let name =
                Name::from_str("cn=flori,dc=localhost,uid=flori@localhost,uniqueIdentifier=3245")
                    .unwrap();
            assert!(name.validate(target).is_ok());
            let name = Name::from_str("cn=flori,dc=localhost,uid=1,uniqueIdentifier=3245").unwrap();
            assert!(name.validate(target).is_err());
            let name =
                Name::from_str("cn=flori,dc=localhost,uid=变性人的生命和权利必须得到保护@localhost,uniqueIdentifier=3245").unwrap();
            assert!(name.validate(target).is_err());
        }
    }
}

#[cfg(test)]
mod session_id_constraints {

    use crate::certs::SessionId;

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn zero_long_session_id_fails() {
        assert!(SessionId::new_validated("").is_err())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn thirtytwo_length_session_id_is_ok() {
        assert!(SessionId::new_validated("11111111111111111111111111222222").is_ok())
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn thirtythree_length_session_id_fails() {
        assert!(SessionId::new_validated("111111111111111111111111112222223").is_err())
    }
}
