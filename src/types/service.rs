// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[cfg(feature = "reqwest")]
type Url = url::Url;
#[cfg(not(feature = "reqwest"))]
type Url = String;

use crate::errors::ConstraintError;
use crate::Constrained;

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A resource representing information about a discoverable service for an actor. You can learn more about
/// services and discoverability by reading [section #9](https://docs.polyphony.chat/Protocol%20Specifications/core#9-services) of
/// the core protocol specification.
///
/// This resource contains information about the name of the service that is being made discoverable,
/// the URL of the service provider, and whether this service provider is the primary service provider
/// for the actor.
///
/// For more information, see the [type definition in the core protocol API documentation](https://docs.polyphony.chat/APIs/core/Types/service/)
pub struct Service {
    /// The name of the service.
    pub service: ServiceName,
    /// The base URL of the service provider, not including `/.p2/<service_name>`. Trailing slashes
    /// are allowed. If `(/).p2/<service_name>` is added to the URL specified here, a polyproto
    /// client should be able to access the HTTP API routes provided by the service.
    pub url: Url,
    ///  Whether the service provider specified in the `url` field is the primary service provider
    /// for this service and actor.
    pub primary: bool,
}

impl Service {
    /// Create a new [Service] resource.
    pub fn new(service_name: &str, url: Url, primary: bool) -> Result<Self, ConstraintError> {
        let service_name = ServiceName::new(service_name)?;
        Ok(Self {
            service: service_name,
            url,
            primary,
        })
    }
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
/// A valid service name, formatted according to
/// [section #8.2: Namespaces](https://docs.polyphony.chat/Protocol%20Specifications/core#82-namespaces)
/// in the core protocol specification.
pub struct ServiceName {
    inner: String,
}

impl std::fmt::Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl ServiceName {
    /// Create a new [ServiceName] from a string slice.
    pub fn new(name: &str) -> Result<Self, crate::errors::ConstraintError> {
        let service_name = Self {
            inner: name.to_string(),
        };
        service_name.validate(None)?;
        Ok(service_name)
    }
}
