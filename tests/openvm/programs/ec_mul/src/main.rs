#![no_std]
#![no_main]

extern crate alloc;

use openvm::io::read_vec;
use revm_precompile::bn128::{mul::BYZANTIUM_MUL_GAS_COST, run_mul};
#[allow(unused_imports)]
use {openvm_algebra_guest::IntMod, openvm_pairing_guest::bn254::Bn254G1Affine};

openvm::entry!(main);

openvm_algebra_moduli_setup::moduli_init! {
    "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
}

openvm_ecc_sw_setup::sw_init! {
    Bn254G1Affine,
}

pub fn main() {
    setup_all_moduli();
    setup_all_curves();
    let input = read_vec();
    let expected = read_vec();

    let outcome = run_mul(&input, BYZANTIUM_MUL_GAS_COST, 40_000).unwrap();
    assert_eq!(outcome.bytes, expected);
}
