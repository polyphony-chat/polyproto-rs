// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub static ERR_MSG_HOME_SERVER_MISSING_CA_ATTR: &str =
    "Home servers CSRs and Certificates must have the \"CA\" capability set to true!";
pub static ERR_MSG_ACTOR_CANNOT_BE_CA: &str =
    "Actor CSRs and Certificates must not have \"CA\" capabilities!";
pub static ERR_MSG_SIGNATURE_MISMATCH: &str =
    "Provided signature does not match computed signature!";
pub static ERR_MSG_ACTOR_MISSING_SIGNING_CAPS: &str =
    "Actors require one of the following capabilities: \"DigitalSignature\", \"ContentCommitment\". None provided.";
pub static ERR_MSG_DC_UID_MISMATCH: &str =
    "The domain components found in the DC and UID fields of the Name object do not match!";
pub static ERR_MSG_DC_MISMATCH_ISSUER_SUBJECT: &str =
    "The domain components of the issuer and the subject do not match!";
#[cfg(feature = "types")]
pub static ERR_MSG_CHALLENGE_STRING_LENGTH: &str =
    "Challenge strings must be between 32 and 255 bytes long!";
#[cfg(feature = "types")]
pub static ERR_MSG_FEDERATION_ID_REGEX: &str =
    "Federation IDs must match the regex: \\b([a-z0-9._%+-]+)@([a-z0-9-]+(\\.[a-z0-9-]+)*)";
/// "Base" error types which can be combined into "composite" error types
pub mod base;
/// "Composite" error types which consist of one or more "base" error types
pub mod composite;
