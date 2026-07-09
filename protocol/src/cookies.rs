use core::time::Duration;

use subtle::ConstantTimeEq;
use tai64::Tai64N;

use crate::crypto::{Hash256, hash, mac};
use crate::keys::PublicKey;

const LABEL_MAC_1: &[u8] = b"mac1----";
const LABEL_COOKIE: &[u8] = b"cookie--";
const COOKIE_REFRESH_INTERVAL: Duration = Duration::from_secs(120);

struct LastCookie {
    received_timestamp: Tai64N,
    cookie: [u8; 16],
}

pub struct Generator {
    mac1_key: Hash256,
    #[allow(unused)] // TODO: handle cookie replies
    mac2_key: Hash256,
    last_cookie: Option<LastCookie>,
}

impl Generator {
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            mac1_key: hash(&[LABEL_MAC_1, public_key.as_bytes()]),
            mac2_key: hash(&[LABEL_COOKIE, public_key.as_bytes()]),
            last_cookie: None,
        }
    }

    pub fn add_macs(&self, current_timestamp: &Tai64N, msg: &mut [u8]) {
        let mac_2_offset = msg.len() - 16;
        let mac_1_offset = mac_2_offset - 16;

        let mac_1 = mac(self.mac1_key.as_ref(), &[&msg[..mac_1_offset]]);
        msg[mac_1_offset..mac_2_offset].copy_from_slice(&mac_1);

        if let Some(last_cookie) = self.last_cookie.as_ref()
            && current_timestamp
                .duration_since(&last_cookie.received_timestamp)
                .unwrap_or_default()
                <= COOKIE_REFRESH_INTERVAL
        {
            let mac_2 = mac(&last_cookie.cookie, &[&msg[..mac_2_offset]]);
            msg[mac_2_offset..].copy_from_slice(&mac_2);
        }
    }
}

pub struct Verifier {
    mac1_key: Hash256,
    #[allow(unused)] // TODO: handle cookie replies
    mac2_key: Hash256,
}

impl Verifier {
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            mac1_key: hash(&[LABEL_MAC_1, public_key.as_bytes()]),
            mac2_key: hash(&[LABEL_COOKIE, public_key.as_bytes()]),
        }
    }

    pub fn verify_mac_1(&self, _: &Tai64N, msg: &[u8]) -> bool {
        let mac_2_offset = msg.len() - 16;
        let mac_1_offset = mac_2_offset - 16;

        let mac_1 = mac(self.mac1_key.as_ref(), &[&msg[..mac_1_offset]]);
        mac_1.ct_eq(&msg[mac_1_offset..mac_2_offset]).into()
    }
}
