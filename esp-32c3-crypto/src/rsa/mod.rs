mod publick_key;
use esp_hal::rsa::RsaMode;
pub use publick_key::RsaPublicKey;


mod private_key;
pub use private_key::RsaPrivateKey;

use paste::paste;

pub trait RsaKey {
    const BLOCKSIZE: usize;
    type OperandType;
    const OperandWords: usize;
    const KEYSIZE: usize;
}


macro_rules! implement_rsakey {
    (($x: literal)) => {
        paste! {
            #[derive(Debug)]
            pub struct [<RsaKeySize $x>];
        }
        paste! {
            impl RsaKey for [<RsaKeySize $x>] {
                const BLOCKSIZE: usize = $x / 8;
                type OperandType = [u32; $x / 32];
                const OperandWords: usize = $x / 32;
                const KEYSIZE: usize = $x;
            }
        }
    };

    ($x:tt, $($y:tt),+) => {
        implement_rsakey!($x);
        implement_rsakey!($($y),+);
    };
}


implement_rsakey!(
    (1024),
    (2048),
    (4096)
);