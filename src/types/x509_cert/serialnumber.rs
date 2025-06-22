// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::ops::{Deref, DerefMut};

use log::trace;

use crate::errors::{CertificateConversionError, InvalidInput};

#[derive(Debug, Clone, PartialEq, Eq)]
/// Wrapper type around [x509_cert::serial_number::SerialNumber], providing serde support, if the
/// `serde` feature is enabled. See "De-/serialization value expectations" below for more
/// information.
///
///   [RFC 5280 Section 4.1.2.2.]  Serial Number
///
///   The serial number MUST be a positive integer assigned by the CA to
///   each certificate.  It MUST be unique for each certificate issued by a
///   given CA (i.e., the issuer name and serial number identify a unique
///   certificate).  CAs MUST force the serialNumber to be a non-negative
///   integer.
///
///   Given the uniqueness requirements above, serial numbers can be
///   expected to contain long integers.  Certificate users MUST be able to
///   handle serialNumber values up to 20 octets.  Conforming CAs MUST NOT
///   use serialNumber values longer than 20 octets.
///
///   Note: Non-conforming CAs may issue certificates with serial numbers
///   that are negative or zero.  Certificate users SHOULD be prepared to
///   gracefully handle such certificates.
///
/// ## De-/serialization value expectations
///
/// The serde de-/serialization implementation for [`SerialNumber`] expects a byte slice representing
/// a positive integer.
pub struct SerialNumber(::x509_cert::serial_number::SerialNumber);

impl From<::x509_cert::serial_number::SerialNumber> for SerialNumber {
    fn from(inner: ::x509_cert::serial_number::SerialNumber) -> Self {
        SerialNumber(inner)
    }
}

impl From<SerialNumber> for ::x509_cert::serial_number::SerialNumber {
    fn from(value: SerialNumber) -> Self {
        value.0
    }
}

impl Deref for SerialNumber {
    type Target = ::x509_cert::serial_number::SerialNumber;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SerialNumber {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl SerialNumber {
    /// Create a new [`SerialNumber`] from a byte slice.
    ///
    /// The byte slice **must** represent a positive integer.
    pub fn new(bytes: &[u8]) -> Result<Self, x509_cert::der::Error> {
        x509_cert::serial_number::SerialNumber::new(bytes).map(Into::into)
    }

    /// Borrow the inner byte slice which contains the least significant bytes
    /// of a big endian integer value with all leading zeros stripped.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Try to convert the inner byte slice to a [u128].
    ///
    /// Returns an error if the byte slice is empty,
    /// or if the byte slice is longer than 16 bytes. Leading zeros of byte slices are stripped, so
    /// 17 bytes are allowed, if the first byte is zero.
    pub fn try_as_u128(&self) -> Result<u128, CertificateConversionError> {
        let mut bytes = self.as_bytes().to_vec();
        if bytes.is_empty() {
            return Err(InvalidInput::Length {
                min_length: 1,
                max_length: 16,
                actual_length: 1.to_string(),
            }
            .into());
        }
        if *bytes.first().unwrap() == 0 {
            bytes.remove(0);
        }
        trace!("bytes: {:?}", bytes);
        if bytes.len() > 16 {
            return Err(InvalidInput::Length {
                min_length: 1,
                max_length: 16,
                actual_length: bytes.len().to_string(),
            }
            .into());
        }
        let mut buf = [0u8; 16];
        buf[16 - bytes.len()..].copy_from_slice(&bytes);
        Ok(u128::from_be_bytes(buf))
    }
}

impl TryFrom<SerialNumber> for u128 {
    type Error = CertificateConversionError;

    fn try_from(value: SerialNumber) -> Result<Self, Self::Error> {
        value.try_as_u128()
    }
}

impl From<u128> for SerialNumber {
    fn from(value: u128) -> Self {
        // All u128 values are valid serial numbers, so we can unwrap
        SerialNumber::new(&value.to_be_bytes()).unwrap()
    }
}

impl std::fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let converted_string = String::from_utf8(
            hex::decode(<Self as ToString>::to_string(self)).map_err(|_| core::fmt::Error {})?,
        )
        .map_err(|_| core::fmt::Error {})?;
        f.write_str(&converted_string)
    }
}

#[cfg(feature = "serde")]
mod serde_support {
    use serde::de::Visitor;
    use serde::{Deserialize, Serialize};

    use super::SerialNumber;

    struct SerialNumberVisitor;

    impl<'de> Visitor<'de> for SerialNumberVisitor {
        type Value = SerialNumber;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a byte slice representing a positive integer")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            SerialNumber::new(v).map_err(serde::de::Error::custom)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut bytes: Vec<u8> = Vec::new(); // Create a new Vec to store the bytes
            while let Some(byte) = seq.next_element()? {
                // "Iterate" over the sequence, assuming each element is a byte
                bytes.push(byte) // Push the byte to the Vec
            }
            SerialNumber::new(&bytes).map_err(serde::de::Error::custom) // Create a SerialNumber from the Vec
        }
    }

    impl<'de> Deserialize<'de> for SerialNumber {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            deserializer.deserialize_any(SerialNumberVisitor)
        }
    }

    impl Serialize for SerialNumber {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            serializer.serialize_bytes(self.as_bytes())
        }
    }
}

#[cfg(feature = "sqlx_postgres")]
mod sqlx_postgres_support {
    use super::*;
    impl sqlx::Type<sqlx::Postgres> for SerialNumber {
        fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
            <&str as sqlx::Type<sqlx::Postgres>>::type_info()
        }
    }

    impl<'q> sqlx::Encode<'q, sqlx::Postgres> for SerialNumber {
        fn encode_by_ref(
            &self,
            buf: &mut <sqlx::Postgres as sqlx::Database>::ArgumentBuffer<'q>,
        ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
            <String as sqlx::Encode<'q, sqlx::Postgres>>::encode_by_ref(&self.to_string(), buf)
        }
    }

    impl<'r> sqlx::Decode<'r, sqlx::Postgres> for SerialNumber {
        fn decode(
            value: <sqlx::Postgres as sqlx::Database>::ValueRef<'r>,
        ) -> Result<Self, sqlx::error::BoxDynError> {
            let string = value.as_str()?;
            let number = string
                .parse::<u128>()
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Self::from(number))
        }
    }
}

#[cfg(test)]
mod test {
    use log::trace;
    use serde_json::json;

    use crate::testing_utils::init_logger;

    use super::SerialNumber;

    #[cfg(feature = "sqlx_postgres")]
    async fn test_sqlx_roundtrip_for_value(pool: &sqlx::PgPool, value: u128) {
        let serial_number = SerialNumber::from(value);
        let stringed = value.to_string();

        sqlx::query("INSERT INTO serial_number_test (serial_number) VALUES ($1)")
            .bind(&stringed)
            .execute(pool)
            .await
            .unwrap();

        let result: (SerialNumber,) =
            sqlx::query_as("SELECT serial_number FROM serial_number_test LIMIT 1")
                .fetch_one(pool)
                .await
                .unwrap();

        assert_eq!(result.0, serial_number);
        assert_eq!(result.0.try_as_u128().unwrap(), value);

        sqlx::query("DELETE FROM serial_number_test")
            .execute(pool)
            .await
            .unwrap();
    }

    #[cfg(feature = "sqlx_postgres")]
    #[sqlx::test]
    async fn test_sqlx_roundtrip(pool: sqlx::PgPool) -> sqlx::Result<()> {
        init_logger();

        // Create a temporary table for the test
        sqlx::query(
            "CREATE TABLE serial_number_test (id SERIAL PRIMARY KEY, serial_number TEXT NOT NULL);",
        )
        .execute(&pool)
        .await?;

        test_sqlx_roundtrip_for_value(&pool, 0).await;
        test_sqlx_roundtrip_for_value(&pool, 1).await;
        test_sqlx_roundtrip_for_value(&pool, 1234567890).await;
        test_sqlx_roundtrip_for_value(&pool, u128::MAX).await;

        Ok(())
    }

    #[test]
    fn serialize_deserialize() {
        init_logger();
        let serial_number = SerialNumber::new(&2347812387874u128.to_be_bytes()).unwrap();
        let serialized = json!(serial_number);
        trace!("is_array: {:?}", serialized.is_array());
        trace!("serialized: {}", serialized);
        let deserialized: SerialNumber = serde_json::from_value(serialized).unwrap();

        assert_eq!(serial_number, deserialized);
    }

    #[test]
    fn serial_number_from_to_u128() {
        init_logger();
        let mut val = 0u128;
        loop {
            let serial_number = SerialNumber::new(&val.to_be_bytes()).unwrap();
            let json = json!(serial_number);
            let deserialized: SerialNumber = serde_json::from_value(json).unwrap();
            let u128 = deserialized.try_as_u128().unwrap();
            assert_eq!(u128, val);
            assert_eq!(deserialized, serial_number);
            if val == 0 {
                val = 1;
            }
            if val == u128::MAX {
                break;
            }
            val = match val.checked_mul(2) {
                Some(v) => v,
                None => u128::MAX,
            };
        }
    }

    #[test]
    fn try_as_u128() {
        init_logger();
        let mut val = 1u128;
        loop {
            let serial_number = SerialNumber::new(&val.to_be_bytes()).unwrap();
            let u128 = serial_number.try_as_u128().unwrap();
            assert_eq!(u128, val);
            trace!("u128: {}", u128);
            if val == u128::MAX {
                break;
            }
            val = match val.checked_mul(2) {
                Some(v) => v,
                None => u128::MAX,
            };
        }
    }
}
