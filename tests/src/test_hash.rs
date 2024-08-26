use esp_32c3_crypto::hash::sha::{Hash, ESP_32C3_SHA1, ESP_32C3_SHA224, ESP_32C3_SHA256};
use esp_hal::{peripherals::Peripherals, sha::ShaMode};
use log::{error, info};


pub fn test_hash() {
    let mut error_count = 0;
    match test_sha1() {
        Ok(_) => info!("SHA1 tests passed"),
        Err(e) => {
            error!("SHA1 test failed with: {e}");
            error_count += 1;
        },
    }

    match test_sha224() {
        Ok(_) => info!("SHA224 tests passed"),
        Err(e) => {
            error!("SHA224 test failed with: {e}");
            error_count += 1;
        },
    }

    match test_sha256() {
        Ok(_) => info!("SHA256 tests passed"),
        Err(e) => {
            error!("SHA256 test failed with: {e}");
            error_count += 1;
        },
    }

    log::warn!("{error_count} of 3 hash algortihm tests failed.");
}

fn test_hash_function(data: &[u8], out: &mut [u8], expected: &[u8], hash: &mut Hash) -> Result<(), &'static str> {
    if let Ok(result) = hash.hash(data, out) {
        if result != expected {
            error!("The result ({:?}) does not equal the expected_result ({:?})", result, expected);
            return Err("Hash results do not match");
        }
    } else {
        return Err("Error while hashing");
    }

    Ok(())
}


fn test_sha1() -> Result<(), &'static str>{
    let sha = unsafe { Peripherals::steal().SHA };

    let mut hash = Hash::new(sha, &ESP_32C3_SHA1);

    if hash.output_len() != 20 {
        return Err("Wrong output length")
    }

    match hash.algorithm() {
        ShaMode::SHA256 | ShaMode::SHA224 => {
            return Err("Wrong hash algorithm");
        },
        _ => {},
    }


    if let Ok(_) = hash.hash(&[0; 1], &mut [0; 1]) {
        return Err("Should error with undersized out");
    }

    // Test output with exact size
    test_hash_function(
        "aaaaaaaaaaaaaaaaaaaa".as_bytes(),
        &mut [0; 20],
        &[0x38, 0x66, 0x6b, 0x8b, 0xa5, 0x00, 0xfa, 0xa5, 0xc2, 0x40, 0x6f, 0x45, 0x75, 0xd4, 0x2a, 0x92, 0x37, 0x98, 0x44, 0xc2],
        &mut hash
    )?;

    // Test output with bigger size
    test_hash_function(
        "aaaaaaaaaaaaaaaaaaaa".as_bytes(),
        &mut [0; 40],
        &[0x38, 0x66, 0x6b, 0x8b, 0xa5, 0x00, 0xfa, 0xa5, 0xc2, 0x40, 0x6f, 0x45, 0x75, 0xd4, 0x2a, 0x92, 0x37, 0x98, 0x44, 0xc2],
        &mut hash
    )?;

    Ok(())
}


fn test_sha224() -> Result<(), &'static str>{
    let sha = unsafe { Peripherals::steal().SHA };

    let mut hash = Hash::new(sha, &ESP_32C3_SHA224);

    if hash.output_len() != 28 {
        return Err("Wrong output length")
    }

    match hash.algorithm() {
        ShaMode::SHA256 | ShaMode::SHA1 => {
            return Err("Wrong hash algorithm");
        },
        _ => {},
    }


    let mut out = [0; 27];
    let data = [0; 1];

    if let Ok(_) = hash.hash(&data, &mut out) {
        return Err("Should error with undersized out");
    }

    // Test output with exact size
    test_hash_function(
        "aaaaaaaaaaaaaaaaaaaa".as_bytes(),
        &mut [0; 28],
        &[0x43, 0x58, 0x6e, 0xff, 0x52, 0xcb, 0xaf, 0x9f, 0x22, 0x48, 0x2f, 0x34, 0xa9, 0x43, 0x7f, 0xf4, 0x5b, 0xd2, 0xe7, 0x31, 0x2a, 0xd5, 0x86, 0xb3, 0xdd, 0x82, 0x80, 0x2f],
        &mut hash
    )?;

    // Test output with bigger size
    test_hash_function(
        "aaaaaaaaaaaaaaaaaaaa".as_bytes(),
        &mut [0; 44],
        &[0x43, 0x58, 0x6e, 0xff, 0x52, 0xcb, 0xaf, 0x9f, 0x22, 0x48, 0x2f, 0x34, 0xa9, 0x43, 0x7f, 0xf4, 0x5b, 0xd2, 0xe7, 0x31, 0x2a, 0xd5, 0x86, 0xb3, 0xdd, 0x82, 0x80, 0x2f],
        &mut hash
    )?;

    Ok(())
}


fn test_sha256() -> Result<(), &'static str>{
    let sha = unsafe { Peripherals::steal().SHA };

    let mut hash = Hash::new(sha, &ESP_32C3_SHA256);

    if hash.output_len() != 32 {
        return Err("Wrong output length")
    }

    match hash.algorithm() {
        ShaMode::SHA224 | ShaMode::SHA1 => {
            return Err("Wrong hash algorithm");
        },
        _ => {},
    }


    let mut out = [0; 31];
    let data = [0; 1];

    if let Ok(_) = hash.hash(&data, &mut out) {
        return Err("Should error with undersized out");
    }

    // Test output with exact size
    test_hash_function(
        "aaaaaaaaaaaaaaaaaaaa".as_bytes(),
        &mut [0; 32],
        &[0x42, 0x49, 0x2d, 0xa0, 0x62, 0x34, 0xad, 0x0a, 0xc7, 0x6f, 0x5d, 0x5d, 0xeb, 0xdb, 0x6d, 0x1a, 0xe0, 0x27, 0xcf, 0xfb, 0xe7, 0x46, 0xa1, 0xc1, 0x3b, 0x89, 0xbb, 0x8b, 0xc0, 0x13, 0x91, 0x37],
        &mut hash
    )?;

    // Test output with bigger size
    test_hash_function(
        "aaaaaaaaaaaaaaaaaaaa".as_bytes(),
        &mut [0; 44],
        &[0x42, 0x49, 0x2d, 0xa0, 0x62, 0x34, 0xad, 0x0a, 0xc7, 0x6f, 0x5d, 0x5d, 0xeb, 0xdb, 0x6d, 0x1a, 0xe0, 0x27, 0xcf, 0xfb, 0xe7, 0x46, 0xa1, 0xc1, 0x3b, 0x89, 0xbb, 0x8b, 0xc0, 0x13, 0x91, 0x37],
        &mut hash
    )?;

    Ok(())
}