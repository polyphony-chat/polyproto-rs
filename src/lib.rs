// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

/*!
<div align="center">

[![Discord]][Discord-invite]
[![Matrix]][Matrix-invite]
[![Build][build-shield]][build-url]
[![Coverage][coverage-shield]][coverage-url]
<img src="https://img.shields.io/static/v1?label=Status&message=Alpha&color=blue" alt="Blue status badge, reading 'Alpha'">

</div>

# polyproto

Crate supplying (generic) Rust types and traits to quickly get a
[polyproto](https://docs.polyphony.chat/Protocol%20Specifications/core/) implementation up and
running, as well as an HTTP client for the polyproto API.

Building upon types offered by the [der](https://crates.io/crates/der),
[x509_cert](https://crates.io/crates/x509_cert) and [spki](https://crates.io/crates/spki) crates,
this crate provides a set of types and traits to quickly implement the polyproto specification.
Simply add cryptography and signature algorithm crates of your choice to the mix, and you are ready
to go.

All polyproto certificate types can be converted to and from the types offered by the `x509_cert`
crate.

## Implementing polyproto

Start by implementing the trait [crate::signature::Signature] for a signature algorithm of your
choice. Popular crates for cryptography and signature algorithms supply their own `PublicKey` and
`PrivateKey` types. You should extend upon these types with your own structs and implement the
[crate::key] traits for these new structs.

You can then use the [crate::certs] types to build certificates using your implementations of the
aforementioned traits.

**View the [examples](./examples/)** directory for a simple example on how to implement and use this
crate with the ED25519 signature algorithm.

## Cryptography

This crate provides no cryptographic functionality whatsoever; its sole purpose is to aid in
implementing polyproto by transforming the
[polyproto specification](https://docs.polyphony.chat/Protocol%20Specifications/core/) into
well-defined yet adaptable Rust types.

## Safety

Please refer to the documentation of individual functions for information on which safety guarantees
they provide. Methods returning certificates, certificate requests and other types where the
validity and correctness of the data has a chance of impacting the security of a system always
mention the safety guarantees they provide in their respective documentation.

This crate has not undergone any security audits.

## WebAssembly

This crate is designed to work with the `wasm32-unknown-unknown` target. To compile for `wasm`, you
will have to use the `wasm` feature:

```toml
[dependencies]
polyproto = { version = "0", features = ["wasm"] }
```

## HTTP API client through `reqwest`

If the `reqwest` feature is activated, this crate offers a polyproto HTTP API client, using the
`reqwest` crate.

### Alternatives to `reqwest`

If you would like to implement an HTTP client using something other than `reqwest`, simply enable
the `types` and `serde` features. Using these features, you can implement your own HTTP client, with
the polyproto crate acting as a single source of truth for request and response types, as well as
request routes and methods through the exported `static` `Route`s.

[build-shield]: https://img.shields.io/github/actions/workflow/status/polyphony-chat/polyproto/build_and_test.yml?style=flat
[build-url]: https://github.com/polyphony-chat/polyproto/blob/main/.github/workflows/build_and_test.yml
[coverage-shield]: https://coveralls.io/repos/github/polyphony-chat/polyproto/badge.svg?branch=main
[coverage-url]: https://coveralls.io/github/polyphony-chat/polyproto?branch=main
[Discord]: https://dcbadge.vercel.app/api/server/m3FpcapGDD?style=flat
[Discord-invite]: https://discord.com/invite/m3FpcapGDD
[Matrix]: https://img.shields.io/matrix/polyproto%3Atu-dresden.de?server_fqdn=matrix.org&style=flat&label=Matrix%20Room
[Matrix-invite]: https://matrix.to/#/#polyproto:tu-dresden.de
*/

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    missing_copy_implementations,
    clippy::todo
)]

/// The OID for the `domainComponent` RDN
pub const OID_RDN_DOMAIN_COMPONENT: &str = "0.9.2342.19200300.100.1.25";
/// The OID for the `commonName` RDN
pub const OID_RDN_COMMON_NAME: &str = "2.5.4.3";
/// The OID for the `uniqueIdentifier` RDN
pub const OID_RDN_UNIQUE_IDENTIFIER: &str = "0.9.2342.19200300.100.1.44";
/// The OID for the `uid` RDN
pub const OID_RDN_UID: &str = "0.9.2342.19200300.100.1.1";

use certs::Target;
use errors::base::ConstraintError;

#[cfg(feature = "reqwest")]
/// Ready-to-use API routes, implemented using `reqwest`
pub mod api;
/// Generic polyproto certificate types and traits.
pub mod certs;
/// Error types used in this crate
pub mod errors;
/// polyproto gateway server connection
pub mod gateway;
/// Generic polyproto public- and private key traits.
pub mod key;
/// Generic polyproto signature traits.
pub mod signature;
#[cfg(feature = "types")]
/// Types used in polyproto and the polyproto HTTP/REST APIs
pub mod types;

mod constraints;

pub use der;
pub use spki;
#[cfg(feature = "reqwest")]
pub use url;
pub use x509_cert::name::*;

/// Types implementing [Constrained] can be validated to be well-formed.
///
/// ## `Target` parameter
///
/// The `target` parameter is used to specify the context in which the type should be validated.
/// For example: Specifying a [Target] of `Actor` would also check that the IdCert is not a CA
/// certificate, among other things.
///
/// If the `target` is `None`, the type will be validated without
/// considering this context. If you know the context in which the type will be used, there is no
/// reason to not specify it, and you would only reap negative consequences for not doing so.
///
/// Valid reasons to specify `None` as the `target` are, for example, if you parse a type from a
/// file and do not know the context in which it will be used. Be careful when doing this; ideally,
/// find a way to find out the context in which the type will be used.
///
/// ## Safety
///
/// [Constrained] does not guarantee that a validated type will always be *correct* in the context
/// it is in.
///
/// ### Example
///
/// The password "123" might be well-formed, as in, it meets the validation criteria specified by
/// the system. However, this makes no implications about "123" being the correct password for a
/// given user account.
pub trait Constrained {
    /// Perform validation on the type, returning an error if the type is not well-formed.
    fn validate(&self, target: Option<Target>) -> Result<(), ConstraintError>;
}

#[cfg(test)]
pub(crate) mod testing_utils {
    pub(crate) fn init_logger() {
        if std::env::var("RUST_LOG").is_err() {
            std::env::set_var("RUST_LOG", "trace");
        }
        env_logger::builder()
            .filter_module("crate", log::LevelFilter::Trace)
            .try_init()
            .unwrap_or(());
    }
}

#[cfg(test)]
mod test {
    use der::asn1::Uint;

    use crate::types::x509_cert::SerialNumber;

    fn strip_leading_zeroes(bytes: &[u8]) -> &[u8] {
        if let Some(stripped) = bytes.strip_prefix(&[0u8]) {
            stripped
        } else {
            bytes
        }
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn test_convert_serial_number() {
        let biguint = Uint::new(&[10u8, 240u8]).unwrap();
        assert_eq!(biguint.as_bytes(), &[10u8, 240u8]);
        let serial_number = SerialNumber::new(biguint.as_bytes()).unwrap();
        assert_eq!(
            strip_leading_zeroes(serial_number.as_bytes()),
            biguint.as_bytes()
        );

        let biguint = Uint::new(&[240u8, 10u8]).unwrap();
        assert_eq!(biguint.as_bytes(), &[240u8, 10u8]);
        let serial_number = SerialNumber::new(biguint.as_bytes()).unwrap();
        assert_eq!(
            strip_leading_zeroes(serial_number.as_bytes()),
            biguint.as_bytes()
        );
    }
}
