#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::{
    clock::ClockControl, delay::Delay, peripherals::Peripherals, prelude::*, system::SystemControl
};

use esp_32c3_crypto::rsa::{RsaKeySize1024, RsaKeySize2048, RsaKeySize4096, RsaPrivateKey, RsaPublicKey};


mod test_hash;
mod test_key_parsing;
mod test_signature;


#[entry]
fn main() -> ! {
    let peripherals = Peripherals::take();
    let system = SystemControl::new(peripherals.SYSTEM);

    let clocks = ClockControl::max(system.clock_control).freeze();
    let delay = Delay::new(&clocks);

    esp_println::logger::init_logger_from_env();

    test_hash::test_hash();

    test_key_parsing::test_rsa_key_parsing();

    test_signature::test_rsa_signature_pkcs1v15();

    loop {
        log::info!("Tests done!");
        delay.delay(30.secs());
    }
}

