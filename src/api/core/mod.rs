// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::time::UNIX_EPOCH;

use crate::types::x509_cert::SerialNumber;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::certs::idcert::IdCert;
use crate::certs::idcsr::IdCsr;
use crate::certs::{PublicKeyInfo, SessionId};
use crate::errors::{ConversionError, RequestError};
use crate::key::PublicKey;
use crate::signature::Signature;
use crate::types::routes::core::v1::*;
use crate::types::{ChallengeString, EncryptedPkm, FederationId, Service, ServiceName};

use super::{HttpClient, HttpResult};

/// Get the current UNIX timestamp according to the system clock.
pub fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

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
    ///
    /// ## Safety guarantees
    ///
    /// The resulting [IdCert] is verified and has the same safety guarantees as specified under
    /// [IdCert::full_verify_home_server()], as this method calls that method internally.
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
        log::debug!("Received IdCert: \n{}", pem);
        let id_cert = IdCert::<S, P>::from_pem_unchecked(&pem)?;
        match id_cert.full_verify_home_server(
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ) {
            Ok(_) => (),
            Err(e) => return Err(RequestError::ConversionError(e.into())),
        };
        Ok(id_cert)
    }

    /// Request the server's public [IdCert]. Specify a unix timestamp to get the IdCert which was
    /// valid at that time. If no timestamp is provided, the current IdCert is returned.
    ///
    /// ## Safety guarantees
    ///
    /// The resulting [IdCert] is verified and has the same safety guarantees as specified under
    /// [IdCert::full_verify_home_server()], as this method calls that method internally.
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
        let id_cert = IdCert::<S, P>::from_pem_unchecked(&pem)?;
        match id_cert.full_verify_home_server(unix_time.unwrap_or(current_unix_time())) {
            Ok(_) => (),
            Err(e) => return Err(RequestError::ConversionError(e.into())),
        };
        Ok(id_cert)
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
    ///
    /// ## Safety guarantees
    ///
    /// The resulting [IdCert]s are not verified. The caller is responsible for verifying the correctness
    /// of these `IdCert`s using [IdCert::full_verify_actor()] before using them.
    pub async fn get_actor_id_certs<S: Signature, P: PublicKey<S>>(
        &self,
        fid: &str,
        unix_time: Option<u64>,
        session_id: Option<&SessionId>,
    ) -> HttpResult<Vec<IdCertExt<S, P>>> {
        let request_url = self
            .url
            .join(&format!("{}{}", GET_ACTOR_IDCERTS.path, fid))?;
        let mut request = self
            .client
            .request(GET_ACTOR_IDCERTS.method.clone(), request_url);
        let body = match (unix_time, session_id) {
            // PRETTYFYME
            (Some(time), Some(session)) => {
                Some(json!({ "timestamp": time, "session_id": session.to_string() }))
            }
            (Some(time), None) => Some(json!({"timestamp": time})),
            (None, Some(session)) => Some(json!({"session_id": session.to_string()})),
            (None, None) => None,
        };
        if let Some(body) = body {
            request = request.body(body.to_string());
        }
        let response = request.send().await;
        let pems = HttpClient::handle_response::<Vec<IdCertExtJson>>(response).await?;
        let mut vec_idcert = Vec::new();
        for json in pems.into_iter() {
            vec_idcert.push(IdCertExt::try_from(json)?);
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
        let request_url = self.url.join(DELETE_SESSION.path)?;
        let body = json!({ "session_id": session_id.to_string() });
        self.client
            .request(DELETE_SESSION.method.clone(), request_url)
            .body(body.to_string())
            .send()
            .await?;
        Ok(())
    }

    // TODO: Test discover_services and discover_service
    /// Fetch a list of all services that the actor specified in the `actor_fid` argument has made
    /// discoverable.
    ///
    /// ## Parameters
    ///
    /// `limit`: How many results to return at maximum. Omitting this value will return all existing
    /// results.
    pub async fn discover_services(
        &self,
        actor_fid: &FederationId,
        limit: Option<u32>,
    ) -> HttpResult<Vec<Service>> {
        let request_url = self
            .url
            .join(DISCOVER_SERVICE_ALL.path)?
            .join(&actor_fid.to_string())?;
        let mut request = self
            .client
            .request(DISCOVER_SERVICE_ALL.method.clone(), request_url);
        if let Some(limit) = limit {
            request = request.body(
                json!({
                    "limit": limit
                })
                .to_string(),
            );
        }
        let response = request.send().await;
        HttpClient::handle_response::<Vec<Service>>(response).await
    }

    /// Fetch a list of services an actor is registered with, filtered by `service_name`.
    ///
    /// ## Parameters
    ///
    /// `limit`: Whether to limit the amount of returned results. Not specifying a limit will
    /// return all services. Specifying a limit value of 1 will return only the primary
    /// service provider.
    pub async fn discover_service(
        &self,
        actor_fid: &FederationId,
        service_name: &ServiceName,
        limit: Option<u32>,
    ) -> HttpResult<Vec<Service>> {
        let request_url = self
            .url
            .join(&format!("{}{}", DISCOVER_SERVICE_SINGULAR.path, actor_fid))?;
        let mut request = self
            .client
            .request(DISCOVER_SERVICE_SINGULAR.method.clone(), request_url);
        if let Some(limit) = limit {
            request = request.body(
                json!({
                    "limit": limit,
                    "service": service_name
                })
                .to_string(),
            );
        } else {
            request = request.body(
                json!({
                    "service": service_name
                })
                .to_string(),
            );
        }
        let response = request.send().await;
        HttpClient::handle_response::<Vec<Service>>(response).await
    }
}

// Core Routes: Registration needed
impl HttpClient {
    /// Rotate your keys for a given session. The `session_id` in the supplied [IdCsr] must
    /// correspond to the session token used in the authorization-Header.
    ///
    /// Returns the new [IdCert] and a token which can be used to authenticate future requests.
    ///
    /// ## Safety guarantees
    ///
    /// The resulting [IdCert] is not verified. The caller is responsible for verifying the correctness
    /// of this `IdCert` using either [IdCert::full_verify_actor()] or [IdCert::full_verify_home_server()].
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
        let response_value = HttpClient::handle_response::<IdCertToken>(request_response).await?;
        let id_cert = IdCert::<S, P>::from_pem_unchecked(&response_value.id_cert.to_string())?;
        Ok((id_cert, response_value.token))
    }

    /// Upload encrypted private key material to the server for later retrieval. The upload size
    /// must not exceed the server's maximum upload size for this route. This is usually not more
    /// than 10kb and can be as low as 800 bytes, depending on the server configuration.
    ///
    /// The `data` parameter is a vector of [EncryptedPkm] which contains the serial number of the
    /// ID-Cert and the encrypted private key material. Naturally, the server cannot check the
    /// contents of the encrypted private key material. However, it is recommended to store the data
    /// in a `SubjectPublicKeyInfo` structure, where the public key is the private key material.
    pub async fn upload_encrypted_pkm(&self, data: Vec<EncryptedPkm>) -> HttpResult<()> {
        let mut body = Vec::new();
        for pkm in data.iter() {
            body.push(json!(pkm));
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
            body.push(json!(serial.try_as_u128()?));
        }
        let request = self
            .client
            .request(GET_ENCRYPTED_PKM.method.clone(), request_url)
            .body(json!(body).to_string());
        let response =
            HttpClient::handle_response::<Vec<EncryptedPkm>>(request.send().await).await?;
        let mut vec_pkm = Vec::new();
        for pkm in response.into_iter() {
            vec_pkm.push(pkm);
        }
        Ok(vec_pkm)
    }

    /// Delete encrypted private key material from the server. The serials must match the
    /// serial numbers of ID-Certs that the client has uploaded key material for.
    pub async fn delete_encrypted_pkm(&self, serials: Vec<SerialNumber>) -> HttpResult<()> {
        let request_url = self.url.join(DELETE_ENCRYPTED_PKM.path)?;
        let mut body = Vec::new();
        for serial in serials.iter() {
            body.push(json!(serial.try_as_u128()?));
        }
        self.client
            .request(DELETE_ENCRYPTED_PKM.method.clone(), request_url)
            .body(json!(body).to_string())
            .send()
            .await?;
        Ok(())
    }

    /// Retrieve the maximum upload size for encrypted private key material, in bytes.
    pub async fn get_pkm_upload_size_limit(&self) -> HttpResult<u64> {
        let request = self.client.request(
            GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT.method.clone(),
            self.url.join(GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT.path)?,
        );
        let response = request.send().await;
        HttpClient::handle_response::<u64>(response).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Represents an [IdCert] with an additional field `invalidated` which indicates whether the
/// certificate has been invalidated. This type is used in the API as a response to the
/// `GET /.p2/core/v1/idcert/actor/:fid`
/// route. Can be converted to and (try)from [IdCertExtJson].
pub struct IdCertExt<S: Signature, P: PublicKey<S>> {
    /// The [IdCert] itself
    pub id_cert: IdCert<S, P>,
    /// Whether the certificate has been marked as invalidated
    pub invalidated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
/// Stringly typed version of [IdCertExt], used for serialization and deserialization.
pub struct IdCertExtJson {
    /// The [IdCert] as a PEM encoded string
    pub id_cert: String,
    /// Whether the certificate has been marked as invalidated
    pub invalidated: bool,
}

impl<S: Signature, P: PublicKey<S>> From<IdCertExt<S, P>> for IdCertExtJson {
    fn from(id_cert: IdCertExt<S, P>) -> Self {
        Self {
            id_cert: id_cert.id_cert.to_pem(der::pem::LineEnding::LF).unwrap(),
            invalidated: id_cert.invalidated,
        }
    }
}

impl<S: Signature, P: PublicKey<S>> TryFrom<IdCertExtJson> for IdCertExt<S, P> {
    type Error = ConversionError;

    fn try_from(id_cert: IdCertExtJson) -> Result<Self, Self::Error> {
        Ok(Self {
            id_cert: IdCert::from_pem_unchecked(id_cert.id_cert.as_str())?,
            invalidated: id_cert.invalidated,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
/// Represents a pair of an [IdCert] and a token, used in the API as a response when an [IdCsr] has
/// been accepted by the server.
pub struct IdCertToken {
    /// The [IdCert] as a PEM encoded string
    pub id_cert: String,
    /// The token as a string
    pub token: String,
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
