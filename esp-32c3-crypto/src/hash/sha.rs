use esp_hal::peripheral::Peripheral;
use esp_hal::prelude::nb::block;
use esp_hal::sha::{Sha, ShaMode};
use esp_hal::peripherals::SHA;
use esp_hal::Blocking;
use log::error;

#[derive(Clone, Debug)]
pub struct Algorithm {
    pub(crate) hash_algorithm: ShaMode,
    pub(crate) output_len: usize,
}

pub static ESP_32C3_SHA256: Algorithm = Algorithm {
    hash_algorithm: ShaMode::SHA256,
    output_len: 32,
};

pub static ESP_32C3_SHA224: Algorithm = Algorithm {
    hash_algorithm: ShaMode::SHA224,
    output_len: 28,
};

pub static ESP_32C3_SHA1: Algorithm = Algorithm {
    hash_algorithm: ShaMode::SHA1,
    output_len: 20,
};

pub struct Hash {
    sha: Sha<'static, Blocking>,
    algo: &'static Algorithm,
}

impl Hash {
    pub fn new(
        sha_peripheral: impl Peripheral<P = SHA> + 'static,
        algo: &'static Algorithm
        
    ) -> Self {
        Self { 
            sha: Sha::new(sha_peripheral, algo.hash_algorithm, None),
            algo
        }
    }

    pub fn hash<'a>(
        &mut self,
        data: &[u8],
        out: &'a mut [u8]
    ) -> Result<&'a [u8], ()> {
        if out.len() < self.algo.output_len {
            error!("Output buffer is smaller then the output length of hash algorithm {:?}", self.algo.hash_algorithm);
            return Err(());
        }

        let mut remaining = data;
        while remaining.len() > 0 {
            remaining = block!(self.sha.update(remaining))
                .expect(".update() should never fail.");
        }
        
        block!(self.sha.finish(out))
            .expect(".finish() should never fail.");

        Ok(&out[..self.algo.output_len])
    }

    pub fn algorithm(&self) -> ShaMode {
        self.algo.hash_algorithm
    }

    pub fn output_len(&self) -> usize {
        self.algo.output_len
    }
}