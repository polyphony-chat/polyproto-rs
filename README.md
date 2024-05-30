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
running.

## Implementing polyproto

**The crate is currently in an alpha stage. Some functionality is missing, and
things may break or change at any point in time.**

This crate extends upon types offered by [der](https://crates.io/crates/der) and
[spki](https://crates.io/crates/spki). This crate exports both of these crates' types and traits
under the `der` and `spki` modules, respectively. It is also possible to use polyproto together
with the `x509_cert` crate, as all the polyproto certificate types are compatible with the
certificate types from that crate.

Start by implementing the trait [crate::signature::Signature] for a signature algorithm of your
choice. Popular crates for cryptography and signature algorithms supply their own `PublicKey` and
`PrivateKey` types. You should extend upon these types with your own structs and implement the
[crate::key] traits for these new structs.

You can then use the [crate::certs] types to build certificates using your implementations of the
aforementioned traits.

View the [examples](./examples/) directory for a simple example on how to implement and use this
crate.

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

## HTTP API client through reqwest

By default, this crate uses `reqwest` for HTTP requests. `reqwest` is an optional dependency, and
you can disable it by using polyproto with `default-features = false` in your `Cargo.toml`:

```toml
[dependencies]
polyproto = { version = "0", default-features = false, features = ["routes"] }
```

Disabling `reqwest` gives you the ability to use your own HTTP client.

[build-shield]: https://img.shields.io/github/actions/workflow/status/polyphony-chat/polyproto/build_and_test.yml?style=flat
[build-url]: https://github.com/polyphony-chat/polyproto/blob/main/.github/workflows/build_and_test.yml
[coverage-shield]: https://coveralls.io/repos/github/polyphony-chat/polyproto/badge.svg?branch=main
[coverage-url]: https://coveralls.io/github/polyphony-chat/polyproto?branch=main
[Discord]: https://dcbadge.vercel.app/api/server/m3FpcapGDD?style=flat
[Discord-invite]: https://discord.com/invite/m3FpcapGDD
[Matrix]: https://img.shields.io/matrix/polyproto%3Atu-dresden.de?server_fqdn=matrix.org&style=flat&label=Matrix%20Room
[Matrix-invite]: https://matrix.to/#/#polyproto:tu-dresden.de
