// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// "Base" error types which can be combined into "composite" error types
pub mod base;
/// "Composite" error types which consist of one or more "base" error types
pub mod composite;

// TODO
// PRETTYFYME
// This module can be restructured to be a reflection of the src/ file tree. It would then be very
// easy to tell, which file covers error types of which data types
