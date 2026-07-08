use core::{
    array,
    ops::{Deref, DerefMut},
};

use blake2::{Blake2s256, Blake2sMac, Digest};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{self, AeadMutInPlace},
};
use hmac::{Mac, SimpleHmac};
use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

use crate::AEAD_TAG_SIZE;

type HMACBlake2s256 = SimpleHmac<Blake2s256>;

#[derive(Clone, ZeroizeOnDrop, Default, Debug, PartialEq)]
pub(crate) struct Hash256([u8; 32]);

impl From<[u8; 32]> for Hash256 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Hash256 {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Hash256 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Hashes an array of inputs using the Blake2s256 algorithm
pub(crate) fn hash(input: &[&[u8]]) -> Hash256 {
    let mut h = Blake2s256::new();
    for input in input {
        h.update(input);
    }
    Hash256(h.finalize().into())
}

pub(crate) fn init_aead(key: &Hash256) -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, key.as_ref()).unwrap())
}

/// Encrypts data using ChaCha20Poly1305 with a given counter and authentication text
/// The plain text is encrypted in place. `data` must be large enough to hold the 16 byte
/// authentication tag.
pub(crate) fn aead_seal<'a>(
    key: &LessSafeKey,
    counter: u64,
    auth_text: &[u8],
    data: &'a mut [u8],
) -> &'a mut [u8] {
    if data.len() < AEAD_TAG_SIZE {
        panic!("data must be long enough to append tag")
    }
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    let plaintext_len = data.len() - 16;
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(auth_text),
            &mut data[..plaintext_len],
        )
        .unwrap();
    data[plaintext_len..].copy_from_slice(tag.as_ref());
    data
}

#[derive(Debug, Error)]
pub enum OpenError {
    #[error("failed")]
    Failed,
}

/// Decrypts data using ChaCha20Poly1305 with a given counter and authentication text
/// The cipher text is decrypted in place. `data` will be truncated to the length of the
/// plain text.
pub(crate) fn aead_open<'a>(
    key: &LessSafeKey,
    counter: u64,
    auth_text: &[u8],
    cipher_text: &'a mut [u8],
) -> Result<&'a mut [u8], OpenError> {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());

    key.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(auth_text),
        cipher_text,
    )
    .map_err(|_| OpenError::Failed)
}

/// Encrypts data using XChaCha20Poly1305 with a given nonce and authentication text
/// The plain text is encrypted in place. `data` must be large enough to hold the 16 byte
/// authentication tag.
#[allow(unused)] // TODO: implement cookies
pub(crate) fn xaead_seal(
    cipher: &mut XChaCha20Poly1305,
    nonce: [u8; 24],
    auth_text: &[u8],
    data: &mut [u8],
) {
    let plaintext_len = data.len() - 16;
    let tag = cipher
        .encrypt_in_place_detached(&nonce.into(), auth_text, &mut data[..plaintext_len])
        .unwrap();
    data[plaintext_len..].copy_from_slice(&tag);
}

/// Decrypts data using XChaCha20Poly1305 with a given nonce and authentication text
/// The cipher text is decrypted in place.
#[allow(unused)] // TODO: implement cookies
pub(crate) fn xaead_open(
    cipher: &mut XChaCha20Poly1305,
    nonce: [u8; 24],
    auth_text: &[u8],
    cipher_text: &mut [u8],
    tag: &[u8],
) -> Result<(), aead::Error> {
    cipher.decrypt_in_place_detached(&nonce.into(), auth_text, cipher_text, tag.into())
}

/// Computes a 16 byte MAC using the Blake2s256 in keyed mode.
pub(crate) fn mac(key: &[u8], input: &[&[u8]]) -> [u8; 16] {
    let mut h = <Blake2sMac<_> as Mac>::new(key.into());
    for input in input {
        h.update(input);
    }
    h.finalize().into_bytes().into()
}

/// Computes a 32 byte MAC using HMAC+Blake2s256.
pub(crate) fn hmac(key: &[u8], input: &[&[u8]]) -> Hash256 {
    let mut h = <HMACBlake2s256 as Mac>::new_from_slice(key).unwrap(); // key is fixed size
    for input in input {
        h.update(input);
    }
    Hash256(h.finalize().into_bytes().into())
}

/// Derives keys from a shared secret using the KDF algorithm
///
/// Kdfn(key, input) Sets τ0 := Hmac(key,input),τ1 := Hmac(τ0,0x1),τi := Hmac(τ0,τi−1 ∥i), and returns an n-tuple of 32 byte values, (τ1,...,τn).
pub(crate) fn kdf<const N: usize>(key: &[u8], input: &[u8]) -> [Hash256; N] {
    if N == 0 || N > u8::MAX as usize {
        panic!("invalid number of keys")
    }
    let t0 = hmac(key, &[input]);
    let mut out = array::from_fn(|_| Hash256::default());
    out[0] = hmac(t0.as_ref(), &[&[1u8]]);
    for i in 1..N {
        out[i] = hmac(t0.as_ref(), &[out[i - 1].as_ref(), &[(i + 1) as u8]]);
    }
    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn kdf_vectors() {
        // taken from https://github.com/WireGuard/wireguard-go/blob/f333402bd9cbe0f3eeb02507bd14e23d7d639280/device/kdf_test.go#L29
        let tests: &[(&[u8], &[u8], [u8; 32], [u8; 32], [u8; 32])] = &[
            (
                &[0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65, 0x79],
                &[0x74, 0x65, 0x73, 0x74, 0x2d, 0x69, 0x6e, 0x70, 0x75, 0x74],
                [
                    0x6f, 0x0e, 0x5a, 0xd3, 0x8d, 0xab, 0xa1, 0xbe, 0xa8, 0xa0, 0xd2, 0x13, 0x68,
                    0x87, 0x36, 0xf1, 0x97, 0x63, 0x23, 0x93, 0x05, 0xe0, 0xf5, 0x8a, 0xba, 0x69,
                    0x7f, 0x9f, 0xfc, 0x41, 0xc6, 0x33,
                ],
                [
                    0xdf, 0x11, 0x94, 0xdf, 0x20, 0x80, 0x2a, 0x4f, 0xe5, 0x94, 0xcd, 0xe2, 0x7e,
                    0x92, 0x99, 0x1c, 0x8c, 0xae, 0x66, 0xc3, 0x66, 0xe8, 0x10, 0x6a, 0xaa, 0x93,
                    0x7a, 0x55, 0xfa, 0x37, 0x1e, 0x8a,
                ],
                [
                    0xfa, 0xc6, 0xe2, 0x74, 0x5a, 0x32, 0x5f, 0x5d, 0xc5, 0xd1, 0x1a, 0x5b, 0x16,
                    0x5a, 0xad, 0x08, 0xb0, 0xad, 0xa2, 0x8e, 0x7b, 0x4e, 0x66, 0x6b, 0x7c, 0x07,
                    0x79, 0x34, 0xa4, 0xd7, 0x6c, 0x24,
                ],
            ),
            (
                &[0x77, 0x69, 0x72, 0x65, 0x67, 0x75, 0x61, 0x72, 0x64],
                &[0x77, 0x69, 0x72, 0x65, 0x67, 0x75, 0x61, 0x72, 0x64],
                [
                    0x49, 0x1d, 0x43, 0xbb, 0xfd, 0xaa, 0x87, 0x50, 0xaa, 0xf5, 0x35, 0xe3, 0x34,
                    0xec, 0xbf, 0xe5, 0x12, 0x99, 0x67, 0xcd, 0x64, 0x63, 0x51, 0x01, 0xc5, 0x66,
                    0xd4, 0xca, 0xef, 0xda, 0x96, 0xe8,
                ],
                [
                    0x1e, 0x71, 0xa3, 0x79, 0xba, 0xef, 0xd8, 0xa7, 0x9a, 0xa4, 0x66, 0x22, 0x12,
                    0xfc, 0xaf, 0xe1, 0x9a, 0x23, 0xe2, 0xb6, 0x09, 0xa3, 0xdb, 0x7d, 0x6b, 0xcb,
                    0xa8, 0xf5, 0x60, 0xe3, 0xd2, 0x5f,
                ],
                [
                    0x31, 0xe1, 0xae, 0x48, 0xbd, 0xdf, 0xbe, 0x5d, 0xe3, 0x8f, 0x29, 0x5e, 0x54,
                    0x52, 0xb1, 0x90, 0x9a, 0x1b, 0x4e, 0x38, 0xe1, 0x83, 0x92, 0x6a, 0xf3, 0x78,
                    0x0b, 0x0c, 0x1e, 0x1f, 0x01, 0x60,
                ],
            ),
            (
                &[],
                &[],
                [
                    0x83, 0x87, 0xb4, 0x6b, 0xf4, 0x3e, 0xcc, 0xfc, 0xf3, 0x49, 0x55, 0x2a, 0x09,
                    0x5d, 0x83, 0x15, 0xc4, 0x05, 0x5b, 0xeb, 0x90, 0x20, 0x8f, 0xb1, 0xbe, 0x23,
                    0xb8, 0x94, 0xbc, 0x2e, 0xd5, 0xd0,
                ],
                [
                    0x58, 0xa0, 0xe5, 0xf6, 0xfa, 0xef, 0xcc, 0xf4, 0x80, 0x7b, 0xff, 0x1f, 0x05,
                    0xfa, 0x8a, 0x92, 0x17, 0x94, 0x57, 0x62, 0x04, 0x0b, 0xce, 0xc2, 0xf4, 0xb4,
                    0xa6, 0x2b, 0xdf, 0xe0, 0xe8, 0x6e,
                ],
                [
                    0x0c, 0xe6, 0xea, 0x98, 0xec, 0x54, 0x8f, 0x8e, 0x28, 0x1e, 0x93, 0xe3, 0x2d,
                    0xb6, 0x56, 0x21, 0xc4, 0x5e, 0xb1, 0x8d, 0xc6, 0xf0, 0xa7, 0xad, 0x94, 0x17,
                    0x86, 0x10, 0xa2, 0xf7, 0x33, 0x8e,
                ],
            ),
        ];

        for (key, input, t0, t1, t2) in tests {
            let [tt0] = kdf::<1>(&key, input);
            assert_eq!(tt0[..], t0[..], "kdf1");

            let [tt0, tt1] = kdf::<2>(&key, input);
            assert_eq!(tt0[..], t0[..], "kdf2 tt0");
            assert_eq!(tt1[..], t1[..], "kdf2 tt1");

            let [tt0, tt1, tt2] = kdf::<3>(&key, input);
            assert_eq!(tt0[..], t0[..], "kdf3 tt0");
            assert_eq!(tt1[..], t1[..], "kdf3 tt1");
            assert_eq!(tt2[..], t2[..], "kdf3 tt2");
        }
    }
}
