#![no_std]
#![no_main]

use openvm::io::read_vec;
#[allow(unused_imports)]
use openvm_ecc_guest::k256::Secp256k1Point;
use revm_precompile::secp256k1::ec_recover_run;
use revm_primitives::Bytes;

openvm_algebra_guest::moduli_macros::moduli_init! {
    "0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F",
    "0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"
}
openvm_ecc_guest::sw_macros::sw_init! {
    Secp256k1Point,
}

openvm::entry!(main);

pub fn main() {
    setup_all_moduli();
    setup_all_curves();

    let expected_address = read_vec();
    let input = read_vec();
    let recovered = ec_recover_run(&Bytes::from(input), 3000).unwrap();
    assert_eq!(recovered.bytes.as_ref(), expected_address);
}
