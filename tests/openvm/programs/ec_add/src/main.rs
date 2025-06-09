#![no_std]
#![no_main]

use openvm::io::read_vec;
#[allow(unused_imports)]
use openvm_pairing_guest::bn254::Bn254G1Affine;
use revm_precompile::bn128::{add::BYZANTIUM_ADD_GAS_COST, run_add};

openvm::init!();

openvm::entry!(main);

pub fn main() {
    setup_all_moduli();
    setup_all_curves();
    let input = read_vec();
    let expected = read_vec();

    let outcome = run_add(&input, BYZANTIUM_ADD_GAS_COST, 500).unwrap();
    assert_eq!(outcome.bytes, expected);
}
