// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use super::Identifer;

pub struct Resource;
pub struct ResourceInformation;

#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccessControl {
    pub private: bool,
    pub allowlist: Vec<Identifer>,
    pub denylist: Vec<Identifer>,
}
