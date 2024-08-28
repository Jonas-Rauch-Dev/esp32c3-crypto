use core::marker::PhantomData;

use esp_hal::peripheral::Peripheral;
use esp_hal::prelude::nb::block;
use esp_hal::sha::{Sha, ShaMode};
use esp_hal::peripherals::SHA;
use esp_hal::Blocking;
use log::error;


pub trait HashAlgorithm {
    const hash_algorithm: ShaMode;
    const output_len: usize;
    const prefix_len: usize;
}


pub struct Esp32C3Sha256;

impl HashAlgorithm for Esp32C3Sha256 {
    const hash_algorithm: ShaMode = ShaMode::SHA256;
    const output_len: usize = 32;
    const prefix_len: usize = 19;
}

pub struct Esp32C3Sha224;
impl HashAlgorithm for Esp32C3Sha224 {
    const hash_algorithm: ShaMode = ShaMode::SHA224;
    const output_len: usize = 28;
    const prefix_len: usize = 19;
}

pub struct Esp32C3Sha1;
impl HashAlgorithm for Esp32C3Sha1 {
    const hash_algorithm: ShaMode = ShaMode::SHA1;
    const output_len: usize = 20;
    const prefix_len: usize = 15;
}

pub struct Hash<HA: HashAlgorithm> {
    sha: Sha<'static, Blocking>,
    phantom: PhantomData<HA>
}

impl<HA: HashAlgorithm> Hash<HA> {
    pub fn new(
        sha_peripheral: impl Peripheral<P = SHA> + 'static,
    ) -> Self {
        Self { 
            sha: Sha::new(sha_peripheral, HA::hash_algorithm, None),
            phantom: PhantomData
        }
    }

    pub fn hash<'a>(
        &mut self,
        data: &[u8],
        out: &'a mut [u8]
    ) -> Result<&'a [u8], ()> {
        if out.len() < HA::output_len {
            error!("Output buffer is smaller then the output length of hash algorithm {:?}", HA::hash_algorithm);
            return Err(());
        }

        let mut remaining = data;
        while remaining.len() > 0 {
            remaining = block!(self.sha.update(remaining))
                .expect(".update() should never fail.");
        }
        
        block!(self.sha.finish(out))
            .expect(".finish() should never fail.");

        Ok(&out[..HA::output_len])
    }

    pub fn algorithm(&self) -> ShaMode {
        HA::hash_algorithm
    }

    pub fn output_len(&self) -> usize {
        HA::output_len
    }
}