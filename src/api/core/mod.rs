// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::certs::idcert::IdCert;
use crate::key::PublicKey;
use crate::signature::Signature;
use crate::types::ChallengeString;

use super::{HttpClient, HttpResult};

// TODO: Use the Routes module to get the correct path for the request

impl HttpClient {
    pub fn get_challenge_string(&self, url: &str) -> HttpResult<ChallengeString> {
        todo!()
    }

    pub fn rotate_server_identity_key<S: Signature, P: PublicKey<S>>(
        &self,
        url: &str,
    ) -> HttpResult<IdCert<S, P>> {
        todo!()
    }
}
