// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Module defining the [ChallengeString] type.
pub mod challenge_string;
/// This module contains wrappers for types from the `der` crate which interface directly with the
/// HTTP API of polyproto. These wrappers enable the types to be serialized and deserialized using
/// the `serde` crate, if the `serde` feature is enabled.
pub mod der;
/// Module defining the [EncryptedPkm] type, as well as related subtypes.
pub mod encrypted_pkm;
/// Module defining the [FederationId] type.
pub mod federation_id;

/// Module defining the [Service] type.
pub mod service;
/// This module contains wrappers for types from the `spki` crate which interface directly with the
/// HTTP API of polyproto. These wrappers enable the types to be serialized and deserialized using
/// the `serde` crate, if the `serde` feature is enabled.
pub mod spki;
/// This module contains wrappers for types from the `x509_cert` crate which interface directly with the
/// HTTP API of polyproto. These wrappers enable the types to be serialized and deserialized using
/// the `serde` crate, if the `serde` feature is enabled.
pub mod x509_cert;

pub use challenge_string::*;
pub use encrypted_pkm::*;
pub use federation_id::*;
pub use service::*;

/// Module defining the [Route] type, as well as `static` endpoints and their associated HTTP methods
/// for the polyproto API. These `static`s can be used as a single source of truth for the API endpoints
/// and what methods to submit to them.
pub mod routes {

    use http::Method;

    #[derive(Debug, Clone)]
    /// A route, consisting of an HTTP method and a path, which is relative to the root of the polyproto
    /// server URL.
    #[allow(missing_docs)]
    pub struct Route {
        pub method: Method,
        pub path: &'static str,
    }

    #[cfg(not(tarpaulin_include))]
    /// [Route]s for the core API of polyproto.
    pub mod core {
        /// [Route]s for version 1 of polyproto.
        pub mod v1 {
            #![allow(missing_docs)]
            use http::Method;

            use super::super::Route;

            pub static GET_CHALLENGE_STRING: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/challenge/",
            };

            pub static GET_NEW_IDCERT: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/idcert/",
            };

            pub static ROTATE_SERVER_IDENTITY_KEY: Route = Route {
                method: Method::PUT,
                path: "/.p2/core/v1/key/server/",
            };

            pub static GET_SERVER_IDCERT: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/idcert/server/",
            };

            pub static GET_ACTOR_IDCERTS: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/idcert/actor/",
            };

            pub static UPDATE_SESSION_IDCERT: Route = Route {
                method: Method::PUT,
                path: "/.p2/core/v1/session/idcert/extern",
            };

            pub static DELETE_SESSION: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/session/",
            };

            pub static ROTATE_SESSION_IDCERT: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/session/idcert/",
            };

            pub static UPLOAD_ENCRYPTED_PKM: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/session/keymaterial/",
            };

            pub static GET_ENCRYPTED_PKM: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/session/keymaterial/",
            };

            pub static DELETE_ENCRYPTED_PKM: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/session/keymaterial/",
            };

            pub static GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/session/keymaterial/size/",
            };

            pub static CREATE_DISCOVERABLE: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/services/",
            };

            pub static DELETE_DISCOVERABLE: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/services/",
            };

            pub static SET_PRIMARY_DISCOVERABLE: Route = Route {
                method: Method::PUT,
                path: "/.p2/core/v1/services/primary/",
            };

            pub static DISCOVER_SERVICE_ALL: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/services/discover/",
            };

            pub static DISCOVER_SERVICE_SINGULAR: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/services/discover/{fid}/{service}/",
            };

            pub static IMPORT_DATA: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/migration/data/",
            };

            pub static EXPORT_DATA: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/data/",
            };

            pub static DELETE_DATA: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/data/",
            };

            pub static SET_UP_REDIRECT: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/migration/redirect/",
            };

            pub static REMOVE_REDIRECT: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/migration/redirect/",
            };

            pub static COMPLETE_KEY_TRIAL: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/keytrial/",
            };

            pub static GET_COMPLETED_KEYTRIALS_AND_RESPONSES: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/keytrial/",
            };

            pub static GET_MESSAGES_TO_BE_RESIGNED: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/messages/",
            };

            pub static REQUEST_MESSAGE_RESIGNING: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/messages/",
            };

            pub static ABORT_MESSAGE_RESIGNING: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/messages/",
            };

            pub static COMMIT_RESIGNED_MESSAGES: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/messages/commit/",
            };

            pub static SET_UP_REDIRECT_EXTERN: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/redirect/extern",
            };

            pub static GET_RESOURCE_BY_ID: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/resource/",
            };

            pub static LIST_UPDATED_RESOURCES: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/resource/resources/",
            };

            pub static UPDATE_RESOURCE_ACCESS: Route = Route {
                method: Method::PUT,
                path: "/.p2/core/v1/resource/",
            };

            pub static UPLOAD_RESOURCE: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/resource/",
            };

            pub static DELETE_RESOURCE: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/resource/",
            };

            pub static GET_RESOURCE_INFO_BY_ID: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/resource/{rid}/info/",
            };
        }
    }
}
