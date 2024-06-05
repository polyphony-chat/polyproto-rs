// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

#[derive(Debug, PartialEq, Clone, Eq, PartialOrd, Ord)]
/// Wrapper around [der::asn1::Ia5String], which provides serde support, if the `serde` feature is
/// enabled.
///
/// ASN.1 `IA5String` type.
///
/// Supports the [International Alphabet No. 5 (IA5)] character encoding, i.e.
/// the lower 128 characters of the ASCII alphabet. (Note: IA5 is now
/// technically known as the International Reference Alphabet or IRA as
/// specified in the ITU-T's T.50 recommendation).
///
/// For UTF-8, use [`String`][`alloc::string::String`].
///
/// [International Alphabet No. 5 (IA5)]: https://en.wikipedia.org/wiki/T.50_%28standard%29
pub struct Ia5String(der::asn1::Ia5String);

impl Ia5String {
    /// Create a new `IA5String`.
    pub fn new<T>(input: &T) -> Result<Self, der::Error>
    where
        T: AsRef<[u8]> + ?Sized,
    {
        Ok(Ia5String(der::asn1::Ia5String::new(input)?))
    }
}

impl Deref for Ia5String {
    type Target = der::asn1::Ia5String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Ia5String {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<der::asn1::Ia5String> for Ia5String {
    fn from(s: der::asn1::Ia5String) -> Self {
        Self(s)
    }
}

impl From<Ia5String> for der::asn1::Ia5String {
    fn from(s: Ia5String) -> Self {
        s.0
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    use super::Ia5String;
    use serde::de::Visitor;
    use serde::{Deserialize, Serialize};

    impl<'de> Deserialize<'de> for Ia5String {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_str(Ia5StringVisitor)
        }
    }

    struct Ia5StringVisitor;

    impl<'de> Visitor<'de> for Ia5StringVisitor {
        type Value = Ia5String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str(
                "a concatenation of characters from the IA5 character set in &str format",
            )
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Ia5String(match der::asn1::Ia5String::new(&v.to_string()) {
                Ok(val) => val,
                Err(e) => return Err(E::custom(e)),
            }))
        }
    }

    impl Serialize for Ia5String {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_str(self.0.to_string().as_str())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_test::{assert_de_tokens, assert_tokens, Token};

    #[test]
    fn ia5string_ser() {
        let ia5string = Ia5String(der::asn1::Ia5String::new("test").unwrap());
        assert_tokens(&ia5string, &[Token::Str("test")]);
        let ia5string = Ia5String(der::asn1::Ia5String::new(&64u64.to_string()).unwrap());
        assert_tokens(&ia5string, &[Token::Str("64")]);
    }

    #[test]
    fn ia5string_de() {
        let ia5string = Ia5String(der::asn1::Ia5String::new("test").unwrap());
        assert_de_tokens(&ia5string, &[Token::Str("test")]);
        let ia5string = Ia5String(der::asn1::Ia5String::new(64u64.to_string().as_str()).unwrap());
        assert_de_tokens(&ia5string, &[Token::Str("64")]);
    }
}
