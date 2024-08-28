use crypto_bigint::Uint;
use esp_hal::{rsa::{operand_sizes::{Op1024, Op2048}, Rsa, RsaMode, RsaModularExponentiation}, Blocking};


pub const fn compute_mprime<const N: usize>(modulus: &Uint<N>) -> u32 {
    let m_inv = modulus.inv_mod2k(32).to_words()[0];
    (-1 * m_inv as i64 % 4294967296) as u32
}

pub const fn compute_r<const LIMBS: usize>(modulus: &Uint<LIMBS>) 
-> Uint<LIMBS>
where [(); LIMBS * 2 + 1]: Sized 
{
    let mut d = [0_u32; LIMBS * 2 + 1];
    d[d.len() - 1] = 1;
    let d = Uint::from_words(d);
    d.const_rem(&modulus.resize()).0.resize()
}


pub fn run_expo_1024(
    rsa: &mut Rsa<Blocking>,
    exponent: &[u32; 32],
    modulus: &[u32; 32],
    m_prime: u32,
    base: &[u32; 32],
    r: &[u32; 32],
    output: &mut [u32; 32]
)
{
    let mut rsa_exp: RsaModularExponentiation<Op1024, Blocking> = RsaModularExponentiation::new(
        rsa,
        exponent,
        modulus,
        m_prime,
    );

    rsa_exp.start_exponentiation(base, r);
    rsa_exp.read_results(output);
}


pub fn run_expo_2048(
    rsa: &mut Rsa<Blocking>,
    exponent: &[u32; 64],
    modulus: &[u32; 64],
    m_prime: u32,
    base: &[u32; 64],
    r: &[u32; 64],
    output: &mut [u32; 64]
)
{
    let mut rsa_exp: RsaModularExponentiation<Op2048, Blocking> = RsaModularExponentiation::new(
        rsa,
        exponent,
        modulus,
        m_prime,
    );

    rsa_exp.start_exponentiation(base, r);
    rsa_exp.read_results(output);
}