use core::str;

use esp_32c3_crypto::{hash::sha::{Esp32C3Sha256, Hash}, padding::pkcs1v15::Pkcs1v15Encrypt, rsa::{RsaKey, RsaKeySize1024, RsaKeySize2048, RsaPrivateKey, RsaPublicKey}};
use esp_hal::{peripherals::Peripherals, rng::Rng, rsa::Rsa};



const test_file: &[u8] = include_bytes!("../test_file.txt");



pub fn test_encryption() {
    if ! test_1024() {
        log::error!("Encryption test for 1024 bit rsa key failed");
    } else {
        log::info!("Encryption test for 1024 bit rsa key succeded");
    };

    if ! test_2048() {
        log::error!("Encryption test for 2048 bit rsa key failed");
    } else {
        log::info!("Encryption test for 2048 bit rsa key succeded");
    };
}

const public_key_1024: &[u8] = include_bytes!("../keys/public_key_1024.der");
const private_key_1024: &[u8] = include_bytes!("../keys/private_key_1024.der");
const enc_1024_test_file: &[u8] = include_bytes!("../encryptions/test_file.enc_1024");
fn test_1024() -> bool {

    let peripherals = unsafe { Peripherals::steal() };
    let mut rng = Rng::new(peripherals.RNG);

    let mut rsa = peripherals.RSA;
    let mut rsa = Rsa::new(rsa, None);

    // Parse Pub key
    let rsa_public_key  = RsaPublicKey::<RsaKeySize1024>::new_from_der(public_key_1024);
    if let Err(e) = rsa_public_key {
            log::error!("Failed to parse 1024 Byte Public Key with error: {:?}", e);
            return false;
    }
    let rsa_public_key = rsa_public_key.unwrap();

    // Parse Priv key
    let rsa_private_key= RsaPrivateKey::<RsaKeySize1024>::new_from_der(private_key_1024);
    if let Err(e) = rsa_private_key {
            log::error!("Failed to Parse 1024 Byte Private Key with error: {:?}", e);
            return false;
    }
    let rsa_private_key= rsa_private_key.unwrap();

    let padding = Pkcs1v15Encrypt;

    // Encrypt the test file
    let mut ciphertext_buffer = [0u8; 128];
    let ciphertext = rsa_public_key.encrypt(&mut rsa, &mut rng, &padding, &test_file, &mut ciphertext_buffer);
    let ciphertext = match ciphertext {
        Ok(c) => c,
        Err(e) => {
            log::error!("Encryption failed with error: {:?}", e);
            return false;
        }
    };

    // Decrypt the encrypted file
    let mut plaintext_buffer = [0u8; RsaKeySize1024::BLOCKSIZE];
    let plaintext = rsa_private_key.decrypt(&mut rsa, &padding, ciphertext, &mut plaintext_buffer);
    let plaintext = match plaintext {
        Ok(c) => c,
        Err(e) => {
            log::error!("Decryption failed with error: {:?}", e);
            return false;
        }
    };

    // Compare test file and decrypted plaintext
    for (i, &b) in plaintext.iter().enumerate() {
        if b != test_file[i] {
            log::error!("Decrypted plaintext does not equal plaintext at position {i}: \nplaintext:\t\t{:?}\ninitial_plaintext:\t\t{:?}", plaintext, test_file);
            return false;
        }
    }

    // Decrypt the openssl encrypted file
    let mut plaintext_buffer = [0u8; RsaKeySize1024::BLOCKSIZE];
    let plaintext = rsa_private_key.decrypt(&mut rsa, &padding, enc_1024_test_file, &mut plaintext_buffer);
    let plaintext = match plaintext {
        Ok(c) => c,
        Err(e) => {
            log::error!("Decryption failed with error: {:?}", e);
            return false;
        }
    };

    // Compare test file and openssl decrypted plaintext
    for (i, &b) in plaintext.iter().enumerate() {
        if b != test_file[i] {
            log::error!("Openssl decrypted plaintext does not equal plaintext at position {i}: \nplaintext:\t\t{:?}\ninitial_plaintext:\t\t{:?}", plaintext, test_file);
            return false;
        }
    }

    true
}


const public_key_2048: &[u8] = include_bytes!("../keys/public_key_2048.der");
const private_key_2048: &[u8] = include_bytes!("../keys/private_key_2048.der");
const enc_2048_test_file: &[u8] = include_bytes!("../encryptions/test_file.enc_2048");

fn test_2048() -> bool {

    let peripherals = unsafe { Peripherals::steal() };
    let mut rng = Rng::new(peripherals.RNG);

    let mut rsa = peripherals.RSA;
    let mut rsa = Rsa::new(rsa, None);

    // Parse Pub key
    let rsa_public_key  = RsaPublicKey::<RsaKeySize2048>::new_from_der(public_key_2048);
    if let Err(e) = rsa_public_key {
            log::error!("Failed to parse 2048 Byte Public Key with error: {:?}", e);
            return false;
    }
    let rsa_public_key = rsa_public_key.unwrap();

    // Parse Priv key
    let rsa_private_key= RsaPrivateKey::<RsaKeySize2048>::new_from_der(private_key_2048);
    if let Err(e) = rsa_private_key {
            log::error!("Failed to Parse 2048 Byte Private Key with error: {:?}", e);
            return false;
    }
    let rsa_private_key= rsa_private_key.unwrap();

    let padding = Pkcs1v15Encrypt;

    // Encrypt the test file
    let mut ciphertext_buffer = [0u8; RsaKeySize2048::BLOCKSIZE];
    let ciphertext = rsa_public_key.encrypt(&mut rsa, &mut rng, &padding, &test_file, &mut ciphertext_buffer);
    let ciphertext = match ciphertext {
        Ok(c) => c,
        Err(e) => {
            log::error!("Encryption failed with error: {:?}", e);
            return false;
        }
    };

    // Decrypt the plain text
    let mut plaintext_buffer = [0u8; RsaKeySize2048::BLOCKSIZE];
    let plaintext = rsa_private_key.decrypt(&mut rsa, &padding, ciphertext, &mut plaintext_buffer);
    let plaintext = match plaintext {
        Ok(c) => c,
        Err(e) => {
            log::error!("Decryption failed with error: {:?}", e);
            return false;
        }
    };

    // Compare test file and decrypted plaintext
    for (i, &b) in plaintext.iter().enumerate() {
        if b != test_file[i] {
            log::error!("Decrypted plaintext does not equal plaintext at position {i}: \nplaintext:\t\t{:?}\ninitial_plaintext:\t\t{:?}", plaintext, test_file);
            return false;
        }
    }

    // Decrypt the openssl encrypted file
    let mut plaintext_buffer = [0u8; 128];
    let plaintext = rsa_private_key.decrypt(&mut rsa, &padding, enc_2048_test_file, &mut plaintext_buffer);
    let plaintext = match plaintext {
        Ok(c) => c,
        Err(e) => {
            log::error!("Decryption failed with error: {:?}", e);
            return false;
        }
    };

    // Compare test file and openssl decrypted plaintext
    for (i, &b) in plaintext.iter().enumerate() {
        if b != test_file[i] {
            log::error!("Openssl decrypted plaintext does not equal plaintext at position {i}: \nplaintext:\t\t{:?}\ninitial_plaintext:\t\t{:?}", plaintext, test_file);
            return false;
        }
    }

    true

}