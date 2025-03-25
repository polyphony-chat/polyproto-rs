// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// This module contains wrappers for types from the `der` crate which interface directly with the
/// HTTP API of polyproto. These wrappers enable the types to be serialized and deserialized using
/// the `serde` crate, if the `serde` feature is enabled.
pub mod der;
/// Module defining the [EncryptedPkm] type, as well as related subtypes.
#[cfg(feature = "types")]
pub mod encrypted_pkm;
/// Module defining the [FederationId] type.
#[cfg(feature = "types")]
pub mod federation_id;

/// Module defining the [Service] type.
#[cfg(feature = "types")]
pub mod service;
/// This module contains wrappers for types from the `spki` crate which interface directly with the
/// HTTP API of polyproto. These wrappers enable the types to be serialized and deserialized using
/// the `serde` crate, if the `serde` feature is enabled.
pub mod spki;
/// This module contains wrappers for types from the `x509_cert` crate which interface directly with the
/// HTTP API of polyproto. These wrappers enable the types to be serialized and deserialized using
/// the `serde` crate, if the `serde` feature is enabled.
pub mod x509_cert;

/// Module defining the [P2Export] type.
#[cfg(feature = "types")]
pub mod p2_export;

/// Module defining the `KeyTrial` type family, including [KeyTrial] and [KeyTrialResponse].
#[cfg(feature = "types")]
pub mod keytrial;

/// Module defining the "Resource adressing with relative roots" (`RawR`) types.
#[cfg(feature = "types")]
pub mod rawr;

#[cfg(feature = "gateway")]
/// Module defining types associated with the polyproto WebSocket gateway.
pub mod gateway;

#[cfg(feature = "types")]
pub use encrypted_pkm::*;
#[cfg(feature = "types")]
pub use federation_id::*;
#[cfg(feature = "types")]
pub use p2_export::*;
#[cfg(feature = "types")]
pub use rawr::*;
#[cfg(feature = "types")]
pub use service::*;

/// Module defining the [Route] type, as well as `static` endpoints and their associated HTTP methods
/// for the polyproto API. These `static`s can be used as a single source of truth for the API endpoints
/// and what methods to submit to them.
#[cfg(feature = "types")]
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

            pub const WELL_KNOWN: Route = Route {
                method: Method::GET,
                path: "/.well-known/polyproto-core",
            };

            pub const GET_CHALLENGE_STRING: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/challenge/",
            };

            pub const GET_NEW_IDCERT: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/idcert/",
            };

            pub const ROTATE_SERVER_IDENTITY_KEY: Route = Route {
                method: Method::PUT,
                path: "/.p2/core/v1/key/server/",
            };

            pub const GET_SERVER_IDCERT: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/idcert/server/",
            };

            pub const GET_ACTOR_IDCERTS: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/idcert/actor/",
            };

            pub const UPDATE_SESSION_IDCERT: Route = Route {
                method: Method::PUT,
                path: "/.p2/core/v1/session/idcert/extern",
            };

            pub const DELETE_SESSION: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/session/",
            };

            pub const ROTATE_SESSION_IDCERT: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/session/idcert/",
            };

            pub const UPLOAD_ENCRYPTED_PKM: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/session/keymaterial/",
            };

            pub const GET_ENCRYPTED_PKM: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/session/keymaterial/",
            };

            pub const DELETE_ENCRYPTED_PKM: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/session/keymaterial/",
            };

            pub const GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/session/keymaterial/size/",
            };

            pub const CREATE_DISCOVERABLE: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/services/",
            };

            pub const DELETE_DISCOVERABLE: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/services/",
            };

            pub const SET_PRIMARY_DISCOVERABLE: Route = Route {
                method: Method::PUT,
                path: "/.p2/core/v1/services/primary/",
            };

            pub const DISCOVER_SERVICE_ALL: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/services/discover/",
            };

            pub const DISCOVER_SERVICE_SINGULAR: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/services/discover/",
            };

            pub const IMPORT_DATA: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/migration/data/",
            };

            pub const EXPORT_DATA: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/data/",
            };

            pub const DELETE_DATA: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/data/",
            };

            pub const SET_UP_REDIRECT: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/migration/redirect/",
            };

            pub const REMOVE_REDIRECT: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/migration/redirect/",
            };

            pub const COMPLETE_KEY_TRIAL: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/keytrial/",
            };

            pub const GET_COMPLETED_KEYTRIALS_AND_RESPONSES: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/keytrial/{fid}/",
            };

            pub const GET_MESSAGES_TO_BE_RESIGNED: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/messages/",
            };

            pub const REQUEST_MESSAGE_RESIGNING: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/messages/",
            };

            pub const ABORT_MESSAGE_RESIGNING: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/messages/",
            };

            pub const COMMIT_RESIGNED_MESSAGES: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/messages/commit/",
            };

            pub const SET_UP_REDIRECT_EXTERN: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/redirect/extern",
            };

            pub const GET_RESOURCE_BY_ID: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/resource/",
            };

            pub const LIST_UPLOADED_RESOURCES: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/resource/resources/",
            };

            pub const UPDATE_RESOURCE_ACCESS: Route = Route {
                method: Method::PUT,
                path: "/.p2/core/v1/resource/",
            };

            pub const UPLOAD_RESOURCE: Route = Route {
                method: Method::POST,
                path: "/.p2/core/v1/resource/",
            };

            pub const DELETE_RESOURCE: Route = Route {
                method: Method::DELETE,
                path: "/.p2/core/v1/resource/",
            };

            pub const GET_RESOURCE_INFO_BY_ID: Route = Route {
                method: Method::GET,
                path: "/.p2/core/v1/resource/{rid}/info/",
            };
        }
    }
}
