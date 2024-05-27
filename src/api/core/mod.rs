// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde_json::json;
use x509_cert::serial_number::SerialNumber;

use crate::certs::idcert::IdCert;
use crate::certs::idcsr::IdCsr;
use crate::certs::{PublicKeyInfo, SessionId};
use crate::key::PublicKey;
use crate::signature::Signature;
use crate::types::routes::core::v1::*;
use crate::types::ChallengeString;

use super::{HttpClient, HttpResult};

// TODO: MLS routes still missing

// Core Routes: No registration needed
impl HttpClient {
    /// Request a [ChallengeString] from the server.
    pub async fn get_challenge_string(&self) -> HttpResult<ChallengeString> {
        let request_url = self.url.join(GET_CHALLENGE_STRING.path)?;
        let request_response = self
            .client
            .request(GET_CHALLENGE_STRING.method.clone(), request_url)
            .send()
            .await;
        HttpClient::handle_response(request_response).await
    }

    /// Request the server to rotate its identity key and return the new [IdCert]. This route is
    /// only available to server administrators.
    pub async fn rotate_server_identity_key<S: Signature, P: PublicKey<S>>(
        &self,
    ) -> HttpResult<IdCert<S, P>> {
        let request_url = self.url.join(ROTATE_SERVER_IDENTITY_KEY.path)?;
        let request_response = self
            .client
            .request(ROTATE_SERVER_IDENTITY_KEY.method.clone(), request_url)
            .send()
            .await;
        let pem = HttpClient::handle_response::<String>(request_response).await?;
        Ok(IdCert::from_pem(
            pem.as_str(),
            Some(crate::certs::Target::HomeServer),
        )?)
    }

    /// Request the server's public [IdCert]. Specify a unix timestamp to get the IdCert which was
    /// valid at that time. If no timestamp is provided, the current IdCert is returned.
    pub async fn get_server_id_cert<S: Signature, P: PublicKey<S>>(
        &self,
        unix_time: Option<u64>,
    ) -> HttpResult<IdCert<S, P>> {
        let request_url = self.url.join(GET_SERVER_PUBLIC_IDCERT.path)?;
        let mut request = self
            .client
            .request(GET_SERVER_PUBLIC_IDCERT.method.clone(), request_url);
        if let Some(time) = unix_time {
            request = request.body(json!({ "timestamp": time }).to_string());
        }
        let response = request.send().await;
        let pem = HttpClient::handle_response::<String>(response).await?;
        Ok(IdCert::from_pem(
            pem.as_str(),
            Some(crate::certs::Target::HomeServer),
        )?)
    }

    /// Request the server's [PublicKeyInfo]. Specify a unix timestamp to get the public key which
    /// the home server used at that time. If no timestamp is provided, the current public key is
    /// returned.
    pub async fn get_server_public_key_info(
        &self,
        unix_time: Option<u64>,
    ) -> HttpResult<PublicKeyInfo> {
        let request_url = self.url.join(GET_SERVER_PUBLIC_KEY.path)?;
        let mut request = self
            .client
            .request(GET_SERVER_PUBLIC_KEY.method.clone(), request_url);
        if let Some(time) = unix_time {
            request = request.body(json!({ "timestamp": time }).to_string());
        }
        let response = request.send().await;
        let pem = HttpClient::handle_response::<String>(response).await?;
        Ok(PublicKeyInfo::from_pem(pem.as_str())?)
    }

    /// Request the [IdCert]s of an actor. Specify the federation ID of the actor to get the IdCerts
    /// of that actor. Returns a vector of IdCerts which were valid for the actor at the specified
    /// time. If no timestamp is provided, the current IdCerts are returned.
    pub async fn get_actor_id_certs<S: Signature, P: PublicKey<S>>(
        &self,
        fid: &str,
        unix_time: Option<u64>,
    ) -> HttpResult<Vec<IdCert<S, P>>> {
        let request_url = self
            .url
            .join(&format!("{}?{}", GET_ACTOR_IDCERTS.path, fid))?;
        let mut request = self
            .client
            .request(GET_ACTOR_IDCERTS.method.clone(), request_url);
        if let Some(time) = unix_time {
            request = request.body(json!({ "timestamp": time }).to_string());
        }
        let response = request.send().await;
        let pems = HttpClient::handle_response::<Vec<String>>(response).await?;
        let mut vec_idcert = Vec::new();
        for pem in pems.into_iter() {
            vec_idcert.push(IdCert::<S, P>::from_pem(
                pem.as_str(),
                Some(crate::certs::Target::Actor),
            )?)
        }
        Ok(vec_idcert)
    }

    /// Inform a foreign server about a new [IdCert] for a session.
    pub async fn update_session_id_cert<S: Signature, P: PublicKey<S>>(
        &self,
        new_cert: IdCert<S, P>,
    ) -> HttpResult<()> {
        let request_url = self.url.join(UPDATE_SESSION_IDCERT.path)?;
        self.client
            .request(UPDATE_SESSION_IDCERT.method.clone(), request_url)
            .body(new_cert.to_pem(der::pem::LineEnding::LF)?)
            .send()
            .await?;
        Ok(())
    }

    /// Tell a server to delete a session, revoking the session token.
    pub async fn delete_session(&self, session_id: &SessionId) -> HttpResult<()> {
        let request_url = self
            .url
            .join(&format!("{}{}", DELETE_SESSION.path, session_id))?;
        self.client
            .request(DELETE_SESSION.method.clone(), request_url)
            .send()
            .await?;
        Ok(())
    }
}

// Core Routes: Registration needed
impl HttpClient {
    pub async fn rotate_session_id_cert<S: Signature, P: PublicKey<S>>(
        &self,
        csr: IdCsr<S, P>,
    ) -> HttpResult<(IdCert<S, P>, String)> {
        todo!()
    }

    pub async fn upload_encrypted_pkm(&self, data: Vec<EncryptedPkm>) -> HttpResult<()> {
        todo!()
    }

    pub async fn get_encrypted_pkm(
        &self,
        serials: Vec<SerialNumber>,
    ) -> HttpResult<Vec<EncryptedPkm>> {
        todo!()
    }

    pub async fn delete_encrypted_pkm(&self, serials: Vec<SerialNumber>) -> HttpResult<()> {
        todo!()
    }

    pub async fn get_pkm_upload_size_limit(&self, url: &str) -> HttpResult<u64> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedPkm {
    pub serial: SerialNumber, // TODO[ser_der](bitfl0wer): Impl Serialize, Deserialize for SerialNumber
    pub encrypted_pkm: String,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_get_challenge_string() {
        let url = "https://example.com/";
        let client = HttpClient::new(url).unwrap();
        let _result = client.get_challenge_string();
    }
}
