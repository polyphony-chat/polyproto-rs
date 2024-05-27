// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use serde::{Deserialize, Serialize};
use serde_json::json;
use x509_cert::serial_number::SerialNumber;

use crate::certs::idcert::IdCert;
use crate::certs::idcsr::IdCsr;
use crate::certs::{PublicKeyInfo, SessionId};
use crate::errors::ConversionError;
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
    /// Rotate your keys for a given session. The `session_id`` in the supplied [IdCsr] must
    /// correspond to the session token used in the authorization-Header.
    pub async fn rotate_session_id_cert<S: Signature, P: PublicKey<S>>(
        &self,
        csr: IdCsr<S, P>,
    ) -> HttpResult<(IdCert<S, P>, String)> {
        let request_url = self.url.join(ROTATE_SESSION_IDCERT.path)?;
        let request_response = self
            .client
            .request(ROTATE_SESSION_IDCERT.method.clone(), request_url)
            .body(csr.to_pem(der::pem::LineEnding::LF)?)
            .send()
            .await;
        let (pem, token) =
            HttpClient::handle_response::<(String, String)>(request_response).await?;
        Ok((
            IdCert::from_pem(pem.as_str(), Some(crate::certs::Target::Actor))?,
            token,
        ))
    }

    /// Upload encrypted private key material to the server for later retrieval. The upload size
    /// must not exceed the server's maximum upload size for this route. This is usually not more
    /// than 10kb and can be as low as 800 bytes, depending on the server configuration.
    pub async fn upload_encrypted_pkm(&self, data: Vec<EncryptedPkm>) -> HttpResult<()> {
        let mut body = Vec::new();
        for pkm in data.iter() {
            body.push(json!({
                "serial_number": pkm.serial_number.to_string(),
                "encrypted_pkm": pkm.key_data
            }));
        }
        let request_url = self.url.join(UPLOAD_ENCRYPTED_PKM.path)?;
        self.client
            .request(UPLOAD_ENCRYPTED_PKM.method.clone(), request_url)
            .body(json!(body).to_string())
            .send()
            .await?;
        Ok(())
    }

    /// Retrieve encrypted private key material from the server. The serial_numbers, if provided,
    /// must match the serial numbers of ID-Certs that the client has uploaded key material for.
    /// If no serial_numbers are provided, the server will return all key material that the client
    /// has uploaded.
    pub async fn get_encrypted_pkm(
        &self,
        serials: Vec<SerialNumber>,
    ) -> HttpResult<Vec<EncryptedPkm>> {
        let request_url = self.url.join(GET_ENCRYPTED_PKM.path)?;
        let mut body = Vec::new();
        for serial in serials.iter() {
            body.push(json!(serial.to_string()));
        }
        let request = self
            .client
            .request(GET_ENCRYPTED_PKM.method.clone(), request_url)
            .body(
                json!({
                    "serial_numbers": body
                })
                .to_string(),
            );
        let response =
            HttpClient::handle_response::<Vec<EncryptedPkmJson>>(request.send().await).await?;
        let mut vec_pkm = Vec::new();
        for pkm in response.into_iter() {
            vec_pkm.push(EncryptedPkm::try_from(pkm)?);
        }
        Ok(vec_pkm)
    }

    pub async fn delete_encrypted_pkm(&self, serials: Vec<SerialNumber>) -> HttpResult<()> {
        todo!()
    }

    pub async fn get_pkm_upload_size_limit(&self, url: &str) -> HttpResult<u64> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Represents encrypted private key material. The `serial` is used to identify the key
/// material. The `encrypted_pkm` is the actual encrypted private key material.
pub struct EncryptedPkm {
    pub serial_number: SerialNumber,
    pub key_data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Stringly typed version of [EncryptedPkm], used for serialization and deserialization.
/// This is necessary because [SerialNumber] from the `x509_cert` crate does not implement
/// `Serialize` and `Deserialize`.
///
/// Implements `From<EncryptedPkm>` and `TryInto<EncryptedPkmJson>` for conversion between the two
/// types.
///
/// (actually, it does not implement `TryInto<EncryptedPkmJson>`. However, [EncryptedPkm] implements
/// `TryFrom<EncryptedPkmJson>`, but you get the idea.)
pub struct EncryptedPkmJson {
    pub serial_number: String,
    pub key_data: String,
}

impl From<EncryptedPkm> for EncryptedPkmJson {
    fn from(pkm: EncryptedPkm) -> Self {
        Self {
            serial_number: pkm.serial_number.to_string(),
            key_data: pkm.key_data,
        }
    }
}

impl TryFrom<EncryptedPkmJson> for EncryptedPkm {
    type Error = ConversionError;

    fn try_from(pkm: EncryptedPkmJson) -> Result<Self, Self::Error> {
        Ok(Self {
            serial_number: SerialNumber::new(pkm.serial_number.as_bytes())?,
            key_data: pkm.key_data,
        })
    }
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
