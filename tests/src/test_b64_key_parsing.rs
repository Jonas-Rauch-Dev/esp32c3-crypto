use esp_32c3_crypto::{padding::pkcs1v15::Pkcs1v15Encrypt, rsa::{RsaKey, RsaKeySize1024, RsaKeySize2048, RsaPrivateKey, RsaPublicKey}};
use esp_hal::{peripherals::Peripherals, rng::Rng, rsa::Rsa};

const public_key_1024: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCr0WsLSj5hWByaWb0AtD4AW5MMFxN7hDXvDVMViuTFi8xlYM2cSnJlMk+5leSBMde+J4jxov7N9GWtQy9yvh4HxxHHqJRMmL3nZj4MZM4W4dZNVfrOCZI+WwjKWIobCvuQO9T4TZ9PvaE3WrQmivCuIISWTVG234Z9s2prlk5VuwIDAQAB";
const private_key_1024: &str = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKvRawtKPmFYHJpZvQC0PgBbkwwXE3uENe8NUxWK5MWLzGVgzZxKcmUyT7mV5IEx174niPGi/s30Za1DL3K+HgfHEceolEyYvedmPgxkzhbh1k1V+s4Jkj5bCMpYihsK+5A71PhNn0+9oTdatCaK8K4ghJZNUbbfhn2zamuWTlW7AgMBAAECgYA6JjH4LDRYdZ2Yj25r4pRpQpTNrrGlR+WI9hV8YPlz8hBG7zAnCPsWTKS2xogDQX8ml/K89NEPmvseXHKefsFiingv6fs4l+Oy9Mb9XayZNavfxhBJQNA+2gWe+54uLIff4QH/NVlFjf9UY6Del4p8N2ib5gItdRCvfEhe1lyQ4QJBANb0a65v51e2DB6MA+9kMOu8qQPm7Gs0iEx+6c2n9hb+nifmVFvUCaBBM/lRpkjEd3U7mJlwNt1LbhkOljMkqP8CQQDMoFsTLNCDDBI20l8zO48MJ+QaHyd1KsrCioMJ4JmiP2BQ8bsspv+r1qL+hnCmKNiahEdDh+UITNREKk5E4jdFAkEAwY6ELCX91gBKd3My0+yPFKbkNmxI9Nvv45ngZFxa/ye1OE5yJeIP7OrppxY7uoiW3MyWQ4xFCw2yDQQSgej/9wJAaobYowTjkDWKjeu7D+rjr4pc35R0cDTU1a5SRaQdly+zLrCJptdRpt3YgPTwVDBTgy12BBwNCeMlZk836/hwmQJBALWJmVoDGYskSa/+SyBp4Wcev3buEmm4WuK3t2iQKwMs9yMsZsU012VQY7X9dNQsjbXtg+tcmVUwQCu71zTaMbs=";

const public_key_2048: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw0o/UP3j4yomZ2uRuCqH/OkwX3iIijtotVA8s82cPhoG9dD9ZX4l2I3tOd3BKOkIhIcoy15vVMF64YVsMyNV261fGhSgesNyhv5mT9HL3PvMMXIfYVtM63abChVzP2IvsuX4gYPD9xfv9Za+7wqlqrdAgLio145jUAodUPZOYJ4ouWgzH11aVMdHhLSff+uU0rrNNa3rYseACMNAossTs+WVgGrAABNbpX58q4TrsUU6g9fKbEOqhHdfGnEmdiZWkbTmZ2QMqw/6Lqtmg+/Rq9a82jGrOoCs6PiJAiCHFVFO3WjUjq8C8Iq6aTPRnlnstdOFPf9TyopY2qA0+BqsgwIDAQAB";
const private_key_2048: &str = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDSj9Q/ePjKiZna5G4Kof86TBfeIiKO2i1UDyzzZw+Ggb10P1lfiXYje053cEo6QiEhyjLXm9UwXrhhWwzI1XbrV8aFKB6w3KG/mZP0cvc+8wxch9hW0zrdpsKFXM/Yi+y5fiBg8P3F+/1lr7vCqWqt0CAuKjXjmNQCh1Q9k5gnii5aDMfXVpUx0eEtJ9/65TSus01retix4AIw0CiyxOz5ZWAasAAE1ulfnyrhOuxRTqD18psQ6qEd18acSZ2JlaRtOZnZAyrD/ouq2aD79Gr1rzaMas6gKzo+IkCIIcVUU7daNSOrwLwirppM9GeWey104U9/1PKiljaoDT4GqyDAgMBAAECggEAHG/ITnvZ3i86Dl8shduzl5FBGPXNNAu4kIZRgIEVGjnh/5NiApBe5GyuOXnf8ZwVQG8J8qsanQXbZdFu0vd3Phi9u2d7gsTI/X032rGa9N+5eQ28IgoQZk0MAGjlMjqS5YL1L67HL0jOCT3dKaOsQfKTMuswssqqDXKbmDl1aj38ZCD6fNgII7e1GM125kmyZEBvCOBmnwie4OGkgDpUTFxPunjM4UHpzNG+5YEC2TUoLZFjxjifE2tWC5HYNY1YA7VBHBW1BqeAtbwx00ZgNtTVdT9y3JesAjRg7zxkEG33wkyJ6LGyooFFmNsjSYT5NSAqZIumVzXCpLO86hFrIQKBgQDfrQ5LenDBywSL7kgdNEWGR3YKn9Y02ykG1D+hJTMwhainVL8W3dthuXEk+p+U8MA+6q402F46dkZ5OrELdgDfofwHrmHCpiztx6MEqQlK/7sZt7LeWZRBWtps+EU05eVq7PAeCeCJ0p6JotCAam6kMFhfPgB8j/uP999HJLRlMwKBgQDfgwvMSVpy09uotxwQ4c3m5Yrm+tSkOQoTHnMB6yDR3AAId0B7SVz+mNLKBDg/mGoeo+5lpnL9ge8U2UnPGW2qMwxNuCfJ8TxzFfeguPXUn3i+CfqZXybwL5lzlPekJLCxoi94+Uubebk37x3qJY9paEjPHlWgL4eSjQH3I7v7cQKBgQCBrCg/Zcp87x/Bp/CyzZ0IzeEHI8bhebT9Ootw9soIdVRjPeRSc2g97W5Ey+88P56UWyWHiXCHYA5XNclyJYU4IQalxVjzqbceWsCNcRnsGvnzXOYbtb8XbH548i3dDvLD3H0QTRWZkTtL+9H4wLtIAKcbACz0Cd0Dh+Yvrn3OtQKBgFZaYuyCSpeiknMUi5taIhrbBFdJAW6ROvs4AGb1WLC7tqeOqzL2nR8gHBBAoRqw4A8Gdsx/Cl43HQ+JA6Mnx97B6jb8tyKmORydmBZYX2HOWu/RGyi2Qmz5dufY3fRk2H9Ikd7DMhrXZF/f2kbkTAwFZlve9GX29wH/yIqbG72BAoGBAJLNAHThe6rg+CzmRXUPlxE2TEnXBkiE2tbH1DNMBegpED7NYxCl3ufWJaXh71eouEcJYMEsnaxcqTm5MRYLwIen6N1BokBZvfdgVu7RkSU53ES1/1bU1ALbQ2CURjJ/nFfR/ipfcG+0KlmKVtARawrNYzJywCW1oFUcyvBtIf7f";

pub fn test_b64_key_parsing() {
    test_1024();
    test_2048();
}

fn test_1024() {

    let peripherals = unsafe { Peripherals::steal() };
    let mut rsa = Rsa::new(peripherals.RSA, None);
    let mut rng = Rng::new(peripherals.RNG);

    let rsa_public_key = RsaPublicKey::<RsaKeySize1024>::new_from_b64_der(public_key_1024);
    if let Err(e) = &rsa_public_key {
            log::error!("Failed to parse 1024 Byte Public Key with error: {:?}", e);
    }
    log::info!("1024 Public Key parsing successfull");
    let rsa_public_key = rsa_public_key.unwrap();

    let rsa_private_key = RsaPrivateKey::<RsaKeySize1024>::new_from_b64_der(private_key_1024);
    if let Err(e) = &rsa_private_key {
            log::error!("Failed to parse 1024 Byte Private Key with error: {:?}", e);
    }
    log::info!("1024 Private Key parsing successfull");
    let rsa_private_key = rsa_private_key.unwrap();

    let padding = Pkcs1v15Encrypt;

    let initialtext = "hello".as_bytes();

    let mut ciphertext_buffer = [0u8; RsaKeySize1024::BLOCKSIZE];
    let ciphertext = rsa_public_key
        .encrypt(&mut rsa, &mut rng, &padding, initialtext, &mut ciphertext_buffer)
        .expect("Should be able to encrpyt with public key");

    let mut plaintext_buffer = [0u8; RsaKeySize1024::BLOCKSIZE];
    let plaintext = rsa_private_key
        .decrypt(&mut rsa, &padding, ciphertext, &mut plaintext_buffer)
        .expect("Should be able to decrypt with private key");

    for (i, &b) in plaintext.iter().enumerate() {
        if initialtext[i] != b {
            log::error!(
                "initialtext and plaintext do not match at char {}: \ninitialtext: \t{:?}\nplaintext: \t{:?}",
                i, initialtext, plaintext
            );
        }
    }
}


fn test_2048() {

    let peripherals = unsafe { Peripherals::steal() };
    let mut rsa = Rsa::new(peripherals.RSA, None);
    let mut rng = Rng::new(peripherals.RNG);

    let rsa_public_key = RsaPublicKey::<RsaKeySize2048>::new_from_b64_der(public_key_2048);
    if let Err(e) = &rsa_public_key {
            log::error!("Failed to parse 2048 Byte Public Key with error: {:?}", e);
    }
    log::info!("2048 Public Key parsing successfull");
    let rsa_public_key = rsa_public_key.unwrap();

    let rsa_private_key = RsaPrivateKey::<RsaKeySize2048>::new_from_b64_der(private_key_2048);
    if let Err(e) = &rsa_private_key {
            log::error!("Failed to parse 2048 Byte Private Key with error: {:?}", e);
    }
    log::info!("2048 Private Key parsing successfull");
    let rsa_private_key = rsa_private_key.unwrap();

    let padding = Pkcs1v15Encrypt;

    let initialtext = "hello".as_bytes();

    let mut ciphertext_buffer = [0u8; RsaKeySize2048::BLOCKSIZE];
    let ciphertext = rsa_public_key
        .encrypt(&mut rsa, &mut rng, &padding, initialtext, &mut ciphertext_buffer)
        .expect("Should be able to encrpyt with public key");

    let mut plaintext_buffer = [0u8; RsaKeySize2048::BLOCKSIZE];
    let plaintext = rsa_private_key
        .decrypt(&mut rsa, &padding, ciphertext, &mut plaintext_buffer)
        .expect("Should be able to decrypt with private key");

    for (i, &b) in plaintext.iter().enumerate() {
        if initialtext[i] != b {
            log::error!(
                "initialtext and plaintext do not match at char {}: \ninitialtext: \t{:?}\nplaintext: \t{:?}",
                i, initialtext, plaintext
            );
        }
    }
}