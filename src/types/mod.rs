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
    #[derive(Debug, Clone)]
    /// A route, consisting of an HTTP method and a path, which is relative to the root of the polyproto
    /// server URL.
    #[allow(missing_docs)]
    pub struct Route {
        pub method: http::Method,
        pub path: &'static str,
    }

    #[cfg(not(tarpaulin_include))]
    /// [Route]s for the core API of polyproto.
    pub mod core {
        /// [Route]s for version 1 of polyproto.
        pub mod v1 {
            #![allow(missing_docs)]
            use super::super::Route;

            pub static GET_CHALLENGE_STRING: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/challenge",
            };

            pub static ROTATE_SERVER_IDENTITY_KEY: Route = Route {
                method: http::Method::PUT,
                path: "/.p2/core/v1/key/server",
            };

            pub static GET_SERVER_PUBLIC_IDCERT: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/idcert/server",
            };

            pub static GET_SERVER_PUBLIC_KEY: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/key/server",
            };

            pub static GET_ACTOR_IDCERTS: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/idcert/actor/",
            };

            pub static UPDATE_SESSION_IDCERT: Route = Route {
                method: http::Method::PUT,
                path: "/.p2/core/v1/session/idcert/extern",
            };

            pub static DELETE_SESSION: Route = Route {
                method: http::Method::DELETE,
                path: "/.p2/core/v1/session/",
            };

            pub static ROTATE_SESSION_IDCERT: Route = Route {
                method: http::Method::POST,
                path: "/.p2/core/v1/session/idcert",
            };

            pub static UPLOAD_ENCRYPTED_PKM: Route = Route {
                method: http::Method::POST,
                path: "/.p2/core/v1/session/keymaterial",
            };

            pub static GET_ENCRYPTED_PKM: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/session/keymaterial",
            };

            pub static DELETE_ENCRYPTED_PKM: Route = Route {
                method: http::Method::DELETE,
                path: "/.p2/core/v1/session/keymaterial",
            };

            pub static GET_ENCRYPTED_PKM_UPLOAD_SIZE_LIMIT: Route = Route {
                method: http::Method::OPTIONS,
                path: "/.p2/core/v1/session/keymaterial",
            };

            pub static CREATE_DISCOVERABLE: Route = Route {
                method: http::Method::POST,
                path: "/.p2/core/v1/services",
            };

            pub static DELETE_DISCOVERABLE: Route = Route {
                method: http::Method::DELETE,
                path: "/.p2/core/v1/services",
            };

            pub static SET_PRIMARY_DISCOVERABLE: Route = Route {
                method: http::Method::PUT,
                path: "/.p2/core/v1/services/primary",
            };

            /// Unlike [DISCOVER_SERVICE_SINGULAR], this route requires only one query parameter: `fid`.
            pub static DISCOVER_SERVICE_ALL: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/services/discover/",
            };

            /// Unlike [DISCOVER_SERVICE_ALL], this route requires two query parameters: `fid` and `service`.
            pub static DISCOVER_SERVICE_SINGULAR: Route = Route {
                method: http::Method::GET,
                path: "/.p2/core/v1/services/discover/",
            };
        }
    }
}
