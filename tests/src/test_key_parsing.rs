use esp_32c3_crypto::rsa::{RsaKeySize1024, RsaKeySize2048, RsaPrivateKey, RsaPublicKey};


const public_key_1024: &[u8] = include_bytes!("../keys/public_key_1024.der");
const private_key_1024: &[u8] = include_bytes!("../keys/private_key_1024.der");

const public_key_2048: &[u8] = include_bytes!("../keys/public_key_2048.der");
const private_key_2048: &[u8] = include_bytes!("../keys/private_key_2048.der");


pub fn test_rsa_key_parsing() {
    let mut error_count = 0;

    // 1024
    let rsa_public_key  = RsaPublicKey::<RsaKeySize1024>::new_from_der(public_key_1024);
    if let Err(e) = rsa_public_key {
            log::error!("Failed to parse 1024 Byte Public Key with error: {:?}", e);
            error_count += 1;
    }
    log::info!("1024 Public Key parsing successfull");

    let rsa_private_key= RsaPrivateKey::<RsaKeySize1024>::new_from_der(private_key_1024);
    if let Err(e) = rsa_private_key {
            log::error!("Failed to Parse 1024 Byte Private Key with error: {:?}", e);
            error_count += 1;
    }
    log::info!("1024 Private Key parsing successfull");

    // 2048
    let rsa_public_key  = RsaPublicKey::<RsaKeySize2048>::new_from_der(public_key_2048);
    if let Err(e) = rsa_public_key {
            log::error!("Failed to parse 2048 Byte Public Key with error: {:?}", e);
            error_count += 1;
    }
    log::info!("2048 Public Key parsing successfull");

    let rsa_private_key  = RsaPrivateKey::<RsaKeySize2048>::new_from_der(private_key_2048);
    if let Err(e) = rsa_private_key {
            log::error!("Failed to parse 2048 Byte Private Key with error: {:?}", e);
            error_count += 1;
    }
    log::info!("2048 Private Key parsing successfull");

    log::warn!("{error_count} of 4 key parsing tests failed.");
}