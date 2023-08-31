/* hmac_drbg.rs

   Attempts to implement HMAC DRBG from NIST SP 800-90A Rev. 1. Chapter 10.1.2.
   https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf

   No reseeding support, or any guarantees that this is correct.
*/

use ring::hmac;

const MAX_RESEED_INTERVAL: u32 = 1000000;

pub struct HmacDrbg {
    v: [u8; 32],
    key: hmac::Key,
    reseed_counter: u32,
}

impl HmacDrbg {
    pub fn new(seed: &[u8], personalization_string: &[u8]) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, seed);
        let mut h = hmac::Context::with_key(&key);
        let mut v = [0x01u8; 32];

        h.update(&v);
        h.update(personalization_string);
        h.update(seed);
        v.copy_from_slice(h.sign().as_ref());

        HmacDrbg {
            key,
            v,
            reseed_counter: 1,
        }
    }

    pub fn generate_bytes(&mut self, requested_bytes: usize) -> Vec<u8> {
        if self.reseed_counter > MAX_RESEED_INTERVAL {
            // Reseed logic here
            eprintln!("Error: RNG reseed interval reached. Exiting.");
            std::process::exit(1);
        }

        let mut random_bytes = Vec::new();
        let mut output = [0u8; 32];

        while random_bytes.len() < requested_bytes {
            let mut h = hmac::Context::with_key(&self.key);
            h.update(&self.v);
            output.copy_from_slice(h.sign().as_ref());
            self.v.copy_from_slice(&output);

            let bytes_to_take = std::cmp::min(32, requested_bytes - random_bytes.len());
            random_bytes.extend_from_slice(&self.v[..bytes_to_take]);
        }

        let mut h = hmac::Context::with_key(&self.key);
        h.update(&self.v);
        output.copy_from_slice(h.sign().as_ref());
        self.v.copy_from_slice(&output);

        self.reseed_counter += requested_bytes as u32;

        random_bytes
    }
}