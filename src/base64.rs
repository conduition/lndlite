//! Base64 encoding utilities, provided because LND requires Base64 encoding
//! for bytes-like types in the REST API.
use crate::DecodeError;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE as BASE64_URL_SAFE};
use base64::engine::Engine as _;
use serde::{Deserialize, Serialize};
use std::{fmt, marker::PhantomData};

pub fn encode_standard(data: impl AsRef<[u8]>) -> String {
    BASE64_STANDARD.encode(data)
}
pub fn encode_urlsafe(data: impl AsRef<[u8]>) -> String {
    BASE64_URL_SAFE.encode(data)
}

pub fn decode_standard<T: TryFrom<Vec<u8>>>(s: impl AsRef<str>) -> Result<T, DecodeError> {
    let bytes: Vec<u8> = BASE64_STANDARD.decode(s.as_ref())?;
    T::try_from(bytes).map_err(|_| DecodeError::InvalidBytes)
}
pub fn decode_urlsafe<T: TryFrom<Vec<u8>>>(s: impl AsRef<str>) -> Result<T, DecodeError> {
    let bytes: Vec<u8> = BASE64_URL_SAFE.decode(s.as_ref())?;
    T::try_from(bytes).map_err(|_| DecodeError::InvalidBytes)
}

#[derive(Clone, Copy, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct Base64<T>(pub T);

impl<T: AsRef<[u8]>> AsRef<[u8]> for Base64<T> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<T: AsRef<[u8]>> Base64<T> {
    pub fn encode_standard(&self) -> String {
        BASE64_STANDARD.encode(self.0.as_ref())
    }
    pub fn encode_url(&self) -> String {
        BASE64_URL_SAFE.encode(self.0.as_ref())
    }
}

impl<T: AsRef<[u8]>> Serialize for Base64<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&encode_standard(&self.0))
    }
}

struct Base64Visitor<T>(PhantomData<T>);

impl<T> serde::de::Visitor<'_> for Base64Visitor<T>
where
    T: TryFrom<Vec<u8>>,
{
    type Value = Base64<T>;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a string in standard base64 format")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        let inner: T = decode_standard(value).map_err(E::custom)?;
        Ok(Base64(inner))
    }
}

impl<'de, T> Deserialize<'de> for Base64<T>
where
    T: TryFrom<Vec<u8>>,
{
    fn deserialize<D>(deserializer: D) -> Result<Base64<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(Base64Visitor::<T>(PhantomData))
    }
}
