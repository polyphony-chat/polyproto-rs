# polyproto

(Generic) Rust types and traits to quickly get a
[polyproto](https://docs.polyphony.chat/Protocol%20Specifications/core/) implementation up and
running.

## Implementing polyproto

This crate extends upon types offered by [der](https://crates.io/crates/der) and
[spki](https://crates.io/crates/spki). As such, these crates are required dependencies for
projects looking to implement polyproto.

Start by implementing the traits in [crate::signature] and [crate::key]. You can then
use the [crate::cert] types to build certificates using your implementations of the
aformentioned traits.

## Cryptography

This crate provides no cryptographic functionality whatsoever; its sole purpose is to aid in
implementing polyproto by transforming the
[polyproto specification](https://docs.polyphony.chat/Protocol%20Specifications/core/) into
well-defined yet adaptable Rust types.
