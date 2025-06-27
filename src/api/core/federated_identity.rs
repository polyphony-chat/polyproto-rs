// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;

mod registration_required {
    use super::*;
    use crate::api::HttpClient;
    use serde_json::json;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
        /// Request the server to rotate its identity key and return the new [IdCert]. This route is
        /// only available to server administrators.
        ///
        /// ## Safety guarantees
        ///
        /// The resulting [IdCert] is verified and has the same safety guarantees as specified under
        /// [IdCert::full_verify_home_server()], as this method calls that method internally.
        pub async fn rotate_server_identity_key(&self) -> HttpResult<IdCert<S, T::PublicKey>> {
            let request_url = self.instance_url.join(ROTATE_SERVER_IDENTITY_KEY.path)?;
            let request_response = self
                .client
                .client
                .request(ROTATE_SERVER_IDENTITY_KEY.method.clone(), request_url)
                .bearer_auth(&self.token)
                .send()
                .await;
            let pem = HttpClient::handle_response::<String>(request_response).await?;
            log::debug!("Received IdCert: \n{pem}");
            let id_cert = IdCert::<S, T::PublicKey>::from_pem_unchecked(&pem)?;
            match id_cert.full_verify_home_server(
                std::time::SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| RequestError::Custom {
                        reason: e.to_string(),
                    })?
                    .as_secs(),
            ) {
                Ok(_) => (),
                Err(e) => return Err(RequestError::ConversionError(e.into())),
            };
            Ok(id_cert)
        }

        /// Tell a server to delete a session, revoking the session token.
        pub async fn delete_session(&self, session_id: &SessionId) -> HttpResult<()> {
            let request_url = self.instance_url.join(DELETE_SESSION.path)?;
            let body = json!({ "session_id": session_id.to_string() });
            self.client
                .client
                .request(DELETE_SESSION.method.clone(), request_url)
                .bearer_auth(&self.token)
                .body(body.to_string())
                .send()
                .await?;
            Ok(())
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
            let request_url = self.instance_url.join(UPLOAD_ENCRYPTED_PKM.path)?;
            self.client
                .client
                .request(UPLOAD_ENCRYPTED_PKM.method.clone(), request_url)
                .bearer_auth(&self.token)
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
            let request_url = self.instance_url.join(GET_ENCRYPTED_PKM.path)?;
            let mut body = Vec::new();
            for serial in serials.iter() {
                body.push(json!(serial.try_as_u128()?));
            }
            let request = self
                .client
                .client
                .request(GET_ENCRYPTED_PKM.method.clone(), request_url)
                .bearer_auth(&self.token)
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
            let request_url = self.instance_url.join(DELETE_ENCRYPTED_PKM.path)?;
            let mut body = Vec::new();
            for serial in serials.iter() {
                body.push(json!(serial.try_as_u128()?));
            }
            self.client
                .client
                .request(DELETE_ENCRYPTED_PKM.method.clone(), request_url)
                .bearer_auth(&self.token)
                .body(json!(body).to_string())
                .send()
                .await?;
            Ok(())
        }
    }
}

mod registration_not_required {
    use serde_json::json;

    use super::*;

    impl HttpClient {
        /// Retrieve the maximum upload size for encrypted private key material, in bytes.
        pub async fn get_pkm_upload_size_limit(&self, instance_url: &Url) -> HttpResult<u64> {
            let request = self.client.request(
                GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT.method.clone(),
                instance_url.join(GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT.path)?,
            );
            let response = request.send().await;
            HttpClient::handle_response::<u64>(response).await
        }
    }

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
        /// Inform a foreign server about a new [IdCert] for a session.
        pub async fn update_session_id_cert(
            &self,
            new_cert: IdCert<S, T::PublicKey>,
        ) -> HttpResult<()> {
            let request_url = self.instance_url.join(UPDATE_SESSION_IDCERT.path)?;
            self.client
                .client
                .request(UPDATE_SESSION_IDCERT.method.clone(), request_url)
                .bearer_auth(&self.token)
                .body(new_cert.to_pem(der::pem::LineEnding::LF)?)
                .send()
                .await?;
            Ok(())
        }
    }

    impl HttpClient {
        /// Request the server's public [IdCert]. Specify a unix timestamp to get the IdCert which was
        /// valid at that time. If no timestamp is provided, the current IdCert is returned.
        ///
        /// ## Safety guarantees
        ///
        /// The resulting [CacheableIdCert] has not been verified. After converting it into an [IdCert],
        /// you should verify it – if the conversion has not done this already.
        /// [IdCert::full_verify_home_server()], as this method calls that method internally.
        pub async fn get_server_id_cert(
            &self,
            unix_time: Option<u64>,
            instance_url: &Url,
        ) -> HttpResult<CacheableIdCert> {
            let request_url = instance_url.join(GET_SERVER_IDCERT.path)?;
            let mut request = self
                .client
                .request(GET_SERVER_IDCERT.method.clone(), request_url);
            if let Some(time) = unix_time {
                request = request.body(json!({ "timestamp": time }).to_string());
            }
            let response = request.send().await;
            trace!("Got response: {response:?}");
            let id_cert = HttpClient::handle_response::<CacheableIdCert>(response).await?;
            Ok(id_cert)
        }

        /// Request the [IdCert]s of an actor. Specify the federation ID of the actor to get the IdCerts
        /// of that actor. Returns a vector of IdCerts which were valid for the actor at the specified
        /// time. If no timestamp is provided, the current IdCerts are returned.
        ///
        /// ## Safety guarantees
        ///
        /// The resulting [CacheableIdCert]s are not verified. The caller is responsible for verifying the correctness
        /// of these `IdCert`s by converting verifying them using [IdCert::full_verify_actor()] before use.
        pub async fn get_actor_id_certs(
            &self,
            fid: &str,
            unix_time: Option<u64>,
            session_id: Option<&SessionId>,
            instance_url: &Url,
        ) -> HttpResult<Vec<CacheableIdCert>> {
            let request_url = instance_url.join(&format!("{}{}", GET_ACTOR_IDCERTS.path, fid))?;
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
            let pems = HttpClient::handle_response::<Vec<CacheableIdCert>>(response).await?;
            let mut vec_idcert = Vec::new();
            for cert in pems.into_iter() {
                vec_idcert.push(cert);
            }
            Ok(vec_idcert)
        }
    }
}
