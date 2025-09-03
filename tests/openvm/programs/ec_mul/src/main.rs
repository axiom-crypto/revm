#![no_std]
#![no_main]

use openvm::io::read_vec;
#[allow(unused_imports)]
use openvm_pairing::bn254::Bn254G1Affine;
use revm_precompile::bn128::{mul::BYZANTIUM_MUL_GAS_COST, run_mul};

openvm::init!();

openvm::entry!(main);

pub fn main() {
    let input = read_vec();
    let expected = read_vec();

    let outcome = run_mul(&input, BYZANTIUM_MUL_GAS_COST, 40_000).unwrap();
    assert_eq!(outcome.bytes, expected);
}
