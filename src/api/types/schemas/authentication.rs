// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::certs::idcert::IdCert;
use crate::errors::composite::ConversionError;
use crate::key::PublicKey;
use crate::signature::Signature;

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct NewIdCert {
    pub actor_name: String,
    pub csr: String,
    pub auth_payload: Option<String>,
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct NewIdCertCreated {
    pub id_cert: String,
    pub token: String,
}

impl<S: Signature, P: PublicKey<S>> TryFrom<NewIdCertCreated> for IdCert<S, P> {
    type Error = ConversionError;

    fn try_from(value: NewIdCertCreated) -> Result<Self, Self::Error> {
        Self::from_pem(&value.id_cert)
    }
}
