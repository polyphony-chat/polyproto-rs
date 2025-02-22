<img src="https://cloud.bitfl0wer.de/apps/files_sharing/publicpreview/2qCxoXJ27yW7QNR?file=/&fileId=1143147&x=256&y=256&a=true" align="left" alt="a purple cog, split in the middle along the horizontal axis with a gap inbetween the two halves. three overlayed, offset sinus-like waves travel through that gap. each wave has a different shade of purple" width="128px" height="auto"></img>

### `polyproto`

![dev-status]
[![Discord]][Discord-invite]
[![Build][build-shield]][build-url]
[![Coverage][coverage-shield]][coverage-url]

Crate supplying (generic) Rust types and traits to quickly get a
[polyproto](https://docs.polyphony.chat/Protocol%20Specifications/core/) implementation up and
running, as well as an HTTP client for the polyproto API.

**[Overview/TL;DR][overview]** • **[crates.io][crates-link]** • **[Protocol Specification][docs]**

## Crate overview

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

[dev-status]: https://img.shields.io/static/v1?label=Status&message=Alpha&color=blue
[build-shield]: https://img.shields.io/github/actions/workflow/status/polyphony-chat/polyproto-rs/build_and_test.yml?style=flat
[build-url]: https://github.com/polyphony-chat/polyproto-rs/blob/main/.github/workflows/build_and_test.yml
[coverage-shield]: https://coveralls.io/repos/github/polyphony-chat/polyproto-rs/badge.svg?branch=main
[coverage-url]: https://coveralls.io/github/polyphony-chat/polyproto-rs?branch=main
[Discord]: https://dcbadge.vercel.app/api/server/m3FpcapGDD?style=flat
[Discord-invite]: https://discord.com/invite/m3FpcapGDD
[crates-link]: https://crates.io/crates/polyproto
[docs]: https://docs.polyphony.chat/Protocol%20Specifications/core/
[overview]: https://docs.polyphony.chat/Overviews/core/

## Logo

The polyproto logo was designed by the wonderful [antidoxi](https://antidoxi.carrd.co/).
