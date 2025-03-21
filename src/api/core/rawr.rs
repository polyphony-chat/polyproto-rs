// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::*;
mod registration_required {
    use http::StatusCode;

    use crate::api::matches_status_code;
    use crate::types::{Resource, ResourceInformation};

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
            let request = self
                .client
                .request_route(&self.instance_url, LIST_UPLOADED_RESOURCES)?
                .bearer_auth(&self.token)
                .query(&limit)
                .query(&sort);
            let response = request.send().await;
            // TODO: Might error if the list is empty/204 is received. Test it.
            HttpClient::handle_response(response).await
        }

        pub async fn update_rawr_resource_access() -> HttpResult<()> {
            todo!()
        }

        pub async fn upload_rawr_resource(resource: &Resource, rid: &str) -> HttpResult<()> {
            todo!()
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

        pub async fn get_own_rawr_resource_info_by_id() -> HttpResult<ResourceInformation> {
            todo!()
        }
    }
}

mod registration_not_required {
    use super::*;

    impl<S: Signature, T: PrivateKey<S>> Session<S, T> {}

    impl HttpClient {
        pub async fn get_rawr_resource_by_id() -> HttpResult<Vec<u8>> {
            todo!()
        }
    }
}
