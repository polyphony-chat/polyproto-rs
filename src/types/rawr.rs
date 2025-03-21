// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::Identifer;

pub struct Resource {
    pub content_type: String,
}

#[cfg_attr(feature = "serde", serde_with::serde_as)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
/// Information about a [Resource], including size, the resource ID and a resources' [ResourceAccessProperties]
pub struct ResourceInformation {
    /// The unique identifier of this resource
    pub resource_id: String,
    #[cfg_attr(feature = "serde", serde_as(as = "DisplayFromStr"))]
    /// Size of this resource, in bytes
    pub size: u64,
    /// Access properties of this resource.
    pub access: ResourceAccessProperties,
}

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// `ResourceAccessProperties` define which actors and instances may access an uploaded resource.
pub struct ResourceAccessProperties {
    /// Whether the resource should be private by default. Private resources can only be accessed by the uploader and by instances and actors declared in the `allowlist`.
    pub private: bool,
    /// A list of actors and/or instances allowed to access this resource.
    pub allowlist: Vec<Identifer>,
    /// A list of actors and/or instances who cannot have access to this resource.
    pub denylist: Vec<Identifer>,
}
