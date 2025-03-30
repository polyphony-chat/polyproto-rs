// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
mod registration_required {
    use std::fmt::Display;

    use http::StatusCode;
    use serde_json::json;

    use crate::api::matches_status_code;
    use crate::types::{Resource, ResourceAccessProperties, ResourceInformation};

    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
    /// Whether the list of [Resources] should be sorted in a specific way. Specific to the
    /// "List uploaded RawR resources"-route.
    pub enum Ordering {
        /// Smallest first
        SizeAsc,
        /// Largest first
        SizeDesc,
        /// Newest first
        NewestFirst,
        /// Oldest first
        OldestFirst,
    }

    impl Display for Ordering {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Ordering::SizeAsc => f.write_str("SizeAsc"),
                Ordering::SizeDesc => f.write_str("SizeDesc"),
                Ordering::NewestFirst => f.write_str("NewestFirst"),
                Ordering::OldestFirst => f.write_str("OldestFirst"),
            }
        }
    }

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {
        /// Query the server for a list of resources you've uploaded.
        ///
        /// ## Parameters
        ///
        /// - `limit`: How many results you'd like to retrieve at maximum. Usually defaults to 50.
        /// - `sort`: Whether the list should be sorted in a specific way.
        pub async fn list_uploaded_rawr_resources(
            &self,
            limit: Option<u32>,
            sort: Option<Ordering>,
        ) -> HttpResult<Vec<ResourceInformation>> {
            let mut request = self
                .client
                .request_route(&self.instance_url, LIST_UPLOADED_RESOURCES)?
                .bearer_auth(&self.token);
            if let Some(limit) = limit {
                request = request.query(&[("limit", &limit.to_string())]);
            }
            if let Some(sort) = sort {
                request = request.query(&[("sort", &sort.to_string())]);
            }
            let response = request.send().await?;
            let status = response.status();
            let response_text = response.text().await?;
            if status == StatusCode::NO_CONTENT || response_text.is_empty() {
                Ok(Vec::new())
            } else {
                serde_json::from_str::<Vec<ResourceInformation>>(&response_text)
                    .map_err(RequestError::from)
            }
        }

        /// Replace the access properties of a `RawR` resource with updated access properties.
        pub async fn update_rawr_resource_access(
            &self,
            rid: &str,
            new_access_properties: ResourceAccessProperties,
        ) -> HttpResult<()> {
            let request = self
                .client
                .client
                .request(
                    UPDATE_RESOURCE_ACCESS.method,
                    self.instance_url
                        .join(UPDATE_RESOURCE_ACCESS.path)?
                        .join(rid)?,
                )
                .body(json!(new_access_properties).to_string())
                .bearer_auth(&self.token);
            let response = request.send().await?;
            matches_status_code(&[StatusCode::NO_CONTENT, StatusCode::OK], response.status())
        }

        /// Upload a `RawR` resource to your home server.
        pub async fn upload_rawr_resource(
            &self,
            resource: Resource,
            rid: &str,
            resource_access_properties: ResourceAccessProperties,
        ) -> HttpResult<()> {
            let request = self
                .client
                .client
                .request(
                    UPDATE_RESOURCE_ACCESS.method,
                    self.instance_url
                        .join(UPDATE_RESOURCE_ACCESS.path)?
                        .join(rid)?,
                )
                .query(&[(
                    "resourceAccessProperties",
                    urlencoding::encode(&json!(resource_access_properties).to_string()),
                )])
                .bearer_auth(&self.token)
                .header("Content-Length", resource.contents.len())
                .multipart(
                    resource
                        .into_multipart()
                        .map_err(|e| RequestError::Custom {
                            reason: e.to_string(),
                        })?,
                );
            let response = request.send().await?;
            matches_status_code(
                &[
                    StatusCode::NO_CONTENT,
                    StatusCode::OK,
                    StatusCode::ACCEPTED,
                    StatusCode::CREATED,
                ],
                response.status(),
            )
        }

        /// Delete a resource by its resource id (rid).
        pub async fn delete_rawr_resource(&self, rid: &str) -> HttpResult<()> {
            let request = self
                .client
                .client
                .request(
                    DELETE_RESOURCE.method,
                    self.instance_url.join(DELETE_RESOURCE.path)?.join(rid)?,
                )
                .bearer_auth(&self.token);
            let response = request.send().await?;
            matches_status_code(&[StatusCode::NO_CONTENT, StatusCode::OK], response.status())
        }
    }
}

mod registration_not_required {
    use crate::types::ResourceInformation;

    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {}

    impl HttpClient {
        /// Retrieve a `RawR` resource by specifying the ID (`rid`) of the resource.
        ///
        /// ## Parameters
        ///
        /// - `host`: The URL of the polyproto instance to query
        pub async fn get_rawr_resource_by_id(
            &self,
            rid: &str,
            token: Option<String>,
            host: &Url,
        ) -> HttpResult<Vec<u8>> {
            let mut request = self.client.request(
                GET_RESOURCE_BY_ID.method,
                host.join(GET_RESOURCE_BY_ID.path)?.join(rid)?,
            );
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            let response = request.send().await?;
            Ok(response.bytes().await?.to_vec())
        }

        /// Retrieve [ResourceInformation] about a `RawR` resource.
        /// ## Parameters
        ///
        /// - `host`: The URL of the polyproto instance to query
        pub async fn get_rawr_resource_info_by_id(
            &self,
            host: &Url,
            rid: &str,
            token: Option<String>,
        ) -> HttpResult<ResourceInformation> {
            let mut request = self.client.request(
                GET_RESOURCE_INFO_BY_ID.method,
                host.join(&GET_RESOURCE_INFO_BY_ID.path.replace(r#"{rid}"#, rid))?,
            );
            if let Some(token) = token {
                request = request.bearer_auth(token);
            }
            let response = request.send().await;
            // BUG: Will error if the list is empty/204 is received.
            HttpClient::handle_response(response).await
        }
    }
}
