use esp_32c3_crypto::{hash::sha::{Esp32C3Sha1, Esp32C3Sha224, Esp32C3Sha256, Hash, HashAlgorithm}, padding::pkcs1v15::Pkcs1v15Sign, rsa::{RsaKey, RsaKeySize1024, RsaKeySize2048, RsaKeySize4096, RsaPrivateKey, RsaPublicKey}, traits::SignatureScheme};
use esp_hal::{peripherals::Peripherals, rng::Rng, rsa::Rsa};

const test_file: &[u8] = include_bytes!("../test_file.txt");


pub fn test_rsa_signature_pkcs1v15() {
    if ! test_rsa_signature_pkcs1v15_1024_sha1() {
        log::error!("pkcs1v15 signature test for 1024 bit rsa key with sha1 failed");
    } else {
        log::info!("pkcs1v15 signature test for 1024 bit rsa key with sha1 succeded");
    };

    if ! test_rsa_signature_pkcs1v15_1024_sha224() {
        log::error!("pkcs1v15 signature test for 1024 bit rsa key with sha224 failed");
    } else {
        log::info!("pkcs1v15 signature test for 1024 bit rsa key with sha224 succeded");
    };

    if ! test_rsa_signature_pkcs1v15_1024_sha256() {
        log::error!("pkcs1v15 signature test for 1024 bit rsa key with sha256 failed");
    } else {
        log::info!("pkcs1v15 signature test for 1024 bit rsa key with sha256 succeded");
    };

}


const public_key_1024: &[u8] = include_bytes!("../keys/public_key_1024.der");
const private_key_1024: &[u8] = include_bytes!("../keys/private_key_1024.der");
const test_file_sign_1024_sha256: &[u8] = include_bytes!("../test_file.txt.sign_1024_sha256");

pub fn test_rsa_signature_pkcs1v15_1024_sha256() -> bool {

    let peripherals = unsafe { Peripherals::steal() };
    let rng = Rng::new(peripherals.RNG);

    let mut rsa = peripherals.RSA;
    let mut rsa = Rsa::new(rsa, None);

    let mut hash = Hash::<Esp32C3Sha256>::new(peripherals.SHA);

    // Parse Pub key
    let rsa_public_key  = RsaPublicKey::<RsaKeySize1024>::new_from_der(public_key_1024);
    if let Err(e) = rsa_public_key {
            log::error!("Failed to parse 1024 Byte Public Key with error: {:?}", e);
            return false;
    }

    // Parse Priv key
    let rsa_private_key= RsaPrivateKey::<RsaKeySize1024>::new_from_der(private_key_1024);
    if let Err(e) = rsa_private_key {
            log::error!("Failed to Parse 1024 Byte Private Key with error: {:?}", e);
            return false;
    }
    let rsa_private_key= rsa_private_key.unwrap();


    // Creat Signature scheme
    let scheme = Pkcs1v15Sign::new::<Esp32C3Sha256>();

    // Hash the test file
    let mut digest_buffer = [0u8; Esp32C3Sha256::output_len];
    let digest = hash.hash(test_file, &mut digest_buffer).unwrap();

    // Create the Signature
    let mut signature_buffer = [0u8; RsaKeySize1024::BLOCKSIZE];
    let signature = scheme
        .sign(&rsa_private_key, rng, &mut rsa, &digest, &mut signature_buffer);

    // Unpack the signature
    let signature = match signature {
        Err(e) => {
            log::error!("Failed to create signature with error: {:?}", e);
            return false;
        },
        Ok(sig) => sig,
    };

    // Compare Signature to openssl version
    for (i, &b) in signature.iter().enumerate() {
        if test_file_sign_1024_sha256[i] != b {
            log::error!("Openssl Signature does not match Esp32c3Crypto Signature at position: {i}");
            return false;
        }
    }

    // TODO: Verify Openssl Signature
    // TODO: Verify Esp32c3 Crypto Signature

    // TODO: Test other Hashes

    true
}


const test_file_sign_1024_sha1: &[u8] = include_bytes!("../test_file.txt.sign_1024_sha1");

pub fn test_rsa_signature_pkcs1v15_1024_sha1() -> bool {

    let peripherals = unsafe { Peripherals::steal() };
    let rng = Rng::new(peripherals.RNG);

    let mut rsa = peripherals.RSA;
    let mut rsa = Rsa::new(rsa, None);

    let mut hash = Hash::<Esp32C3Sha1>::new(peripherals.SHA);

    // Parse Pub key
    let rsa_public_key  = RsaPublicKey::<RsaKeySize1024>::new_from_der(public_key_1024);
    if let Err(e) = rsa_public_key {
            log::error!("Failed to parse 1024 Byte Public Key with error: {:?}", e);
            return false;
    }

    // Parse Priv key
    let rsa_private_key= RsaPrivateKey::<RsaKeySize1024>::new_from_der(private_key_1024);
    if let Err(e) = rsa_private_key {
            log::error!("Failed to Parse 1024 Byte Private Key with error: {:?}", e);
            return false;
    }
    let rsa_private_key= rsa_private_key.unwrap();


    // Creat Signature scheme
    let scheme = Pkcs1v15Sign::new::<Esp32C3Sha1>();

    // Hash the test file
    let mut digest_buffer = [0u8; Esp32C3Sha1::output_len];
    let digest = hash.hash(test_file, &mut digest_buffer).unwrap();

    // Create the Signature
    let mut signature_buffer = [0u8; RsaKeySize1024::BLOCKSIZE];
    let signature = scheme
        .sign(&rsa_private_key, rng, &mut rsa, &digest, &mut signature_buffer);

    // Unpack the signature
    let signature = match signature {
        Err(e) => {
            log::error!("Failed to create signature with error: {:?}", e);
            return false;
        },
        Ok(sig) => sig,
    };

    // Compare Signature to openssl version
    for (i, &b) in signature.iter().enumerate() {
        if test_file_sign_1024_sha1[i] != b {
            log::error!("Openssl Signature does not match Esp32c3Crypto Signature at position: {i}");
            return false;
        }
    }

    // TODO: Verify Openssl Signature
    // TODO: Verify Esp32c3 Crypto Signature

    // TODO: Test other Hashes

    true
}


const test_file_sign_1024_sha224: &[u8] = include_bytes!("../test_file.txt.sign_1024_sha224");

pub fn test_rsa_signature_pkcs1v15_1024_sha224() -> bool {

    let peripherals = unsafe { Peripherals::steal() };
    let rng = Rng::new(peripherals.RNG);

    let mut rsa = peripherals.RSA;
    let mut rsa = Rsa::new(rsa, None);

    let mut hash = Hash::<Esp32C3Sha224>::new(peripherals.SHA);

    // Parse Pub key
    let rsa_public_key  = RsaPublicKey::<RsaKeySize1024>::new_from_der(public_key_1024);
    if let Err(e) = rsa_public_key {
            log::error!("Failed to parse 1024 Byte Public Key with error: {:?}", e);
            return false;
    }

    // Parse Priv key
    let rsa_private_key= RsaPrivateKey::<RsaKeySize1024>::new_from_der(private_key_1024);
    if let Err(e) = rsa_private_key {
            log::error!("Failed to Parse 1024 Byte Private Key with error: {:?}", e);
            return false;
    }
    let rsa_private_key= rsa_private_key.unwrap();


    // Creat Signature scheme
    let scheme = Pkcs1v15Sign::new::<Esp32C3Sha224>();

    // Hash the test file
    let mut digest_buffer = [0u8; Esp32C3Sha224::output_len];
    let digest = hash.hash(test_file, &mut digest_buffer).unwrap();

    // Create the Signature
    let mut signature_buffer = [0u8; RsaKeySize1024::BLOCKSIZE];
    let signature = scheme
        .sign(&rsa_private_key, rng, &mut rsa, &digest, &mut signature_buffer);

    // Unpack the signature
    let signature = match signature {
        Err(e) => {
            log::error!("Failed to create signature with error: {:?}", e);
            return false;
        },
        Ok(sig) => sig,
    };

    // Compare Signature to openssl version
    for (i, &b) in signature.iter().enumerate() {
        if test_file_sign_1024_sha224[i] != b {
            log::error!("Openssl Signature does not match Esp32c3Crypto Signature at position: {i}");
            return false;
        }
    }

    // TODO: Verify Openssl Signature
    // TODO: Verify Esp32c3 Crypto Signature

    // TODO: Test other Hashes

    true
}