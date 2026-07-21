use core::{fmt, str::FromStr};

use base64::{Engine, prelude::BASE64_STANDARD};
use thiserror::Error;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

const KEY_BASE64_LEN: usize = 44;

/// Error parsing a base64-encoded key.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyParseError {
    #[error("invalid base64")]
    InvalidEncoding,

    #[error("invalid key length")]
    InvalidLength,
}

fn key_from_base64(s: &str) -> Result<[u8; 32], KeyParseError> {
    if s.len() != KEY_BASE64_LEN {
        return Err(KeyParseError::InvalidLength);
    }
    let mut buf = [0u8; KEY_BASE64_LEN];
    let n = BASE64_STANDARD
        .decode_slice(s, &mut buf)
        .map_err(|_| KeyParseError::InvalidEncoding)?;
    <[u8; 32]>::try_from(&buf[..n]).map_err(|_| KeyParseError::InvalidLength)
}

fn fmt_key_base64(key: &[u8; 32], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let mut buf = [0u8; KEY_BASE64_LEN];
    let n = BASE64_STANDARD
        .encode_slice(key, &mut buf)
        .map_err(|_| fmt::Error)?;
    f.write_str(core::str::from_utf8(&buf[..n]).map_err(|_| fmt::Error)?)
}

/// A peer public key. Displays and parses as the standard WireGuard base64
/// encoding.
#[derive(Clone, ZeroizeOnDrop, PartialEq, Eq, Hash)]
pub struct PublicKey(pub(crate) XPublicKey);

impl PublicKey {
    /// The raw 32-byte key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl From<[u8; 32]> for PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(XPublicKey::from(bytes))
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(secret: &PrivateKey) -> Self {
        Self(XPublicKey::from(&secret.0))
    }
}

impl FromStr for PublicKey {
    type Err = KeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(key_from_base64(s)?))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_key_base64(self.as_bytes(), f)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

/// A device private key. Parses from the standard WireGuard base64
/// encoding; never printed by `Debug`.
#[derive(Clone, ZeroizeOnDrop)]
pub struct PrivateKey(pub(crate) StaticSecret);

impl PrivateKey {
    /// Generates a new random private key.
    #[cfg(any(test, feature = "std"))]
    pub fn random() -> Self {
        Self(StaticSecret::random())
    }

    /// The corresponding public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(self)
    }

    /// The raw 32-byte key.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Returns the key in the standard WireGuard base64 encoding, kept out
    /// of `Display` so the secret can't be logged by accident.
    #[cfg(feature = "std")]
    pub fn to_base64(&self) -> String {
        BASE64_STANDARD.encode(self.to_bytes())
    }
}

impl From<[u8; 32]> for PrivateKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }
}

impl FromStr for PrivateKey {
    type Err = KeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(key_from_base64(s)?))
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey(…)")
    }
}

#[derive(Clone, ZeroizeOnDrop, Default)]
pub struct PresharedKey([u8; 32]);

impl AsRef<[u8]> for PresharedKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; 32]> for PresharedKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl FromStr for PresharedKey {
    type Err = KeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(key_from_base64(s)?))
    }
}

impl fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PresharedKey(…)")
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::{format, string::ToString};

    use super::*;

    #[test]
    fn key_base64_roundtrip() {
        let secret = PrivateKey::random();
        let public = secret.public_key();
        let encoded = public.to_string();
        assert_eq!(encoded.len(), 44);
        assert_eq!(encoded.parse::<PublicKey>().unwrap(), public);
        assert_eq!(
            BASE64_STANDARD
                .encode(secret.to_bytes())
                .parse::<PrivateKey>()
                .unwrap()
                .public_key(),
            public
        );
        assert_eq!(format!("{secret:?}"), "PrivateKey(…)");

        assert_eq!(
            "!".repeat(44).parse::<PublicKey>().err(),
            Some(KeyParseError::InvalidEncoding)
        );
        assert_eq!(
            BASE64_STANDARD.encode([0u8; 16]).parse::<PublicKey>().err(),
            Some(KeyParseError::InvalidLength)
        );
    }
}
