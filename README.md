# polyproto

(Generic) Rust types and traits to quickly get a
[polyproto](https://docs.polyphony.chat/Protocol%20Specifications/core/) implementation up and
running.

## Implementing polyproto

**The crate is currently in very early (alpha) development. A lot of functionality is missing, and
things may break or change at any point in time.**

This crate extends upon types offered by [der](https://crates.io/crates/der) and
[spki](https://crates.io/crates/spki). As such, these crates are required dependencies for
projects looking to implement polyproto.

Start by implementing the trait [crate::signature::Signature] for a signature algorithm of your
choice. Popular crates for cryptography and signature algorithms supply their own `PublicKey` and
`PrivateKey` types. You should extend upon these types with your own structs and implement the
[crate::key] traits for these new structs.

You can then use the [crate::certs] types to build certificates using your implementations of the
aforementioned traits.

## Cryptography

This crate provides no cryptographic functionality whatsoever; its sole purpose is to aid in
implementing polyproto by transforming the
[polyproto specification](https://docs.polyphony.chat/Protocol%20Specifications/core/) into
well-defined yet adaptable Rust types.
