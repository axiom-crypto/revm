#![no_std]
#![no_main]

#[allow(unused_imports)]
use k256::Secp256k1Point;
use openvm::io::read_vec;
use revm_precompile::secp256k1::ec_recover_run;
use revm_primitives::Bytes;

openvm::init!();

openvm::entry!(main);

pub fn main() {
    let expected_address = read_vec();
    let input = read_vec();
    let recovered = ec_recover_run(&Bytes::from(input), 3000).unwrap();
    assert_eq!(recovered.bytes.as_ref(), expected_address);
}
