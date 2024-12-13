#![no_std]
#![no_main]

extern crate alloc;

use openvm::io::read_vec;
use revm_precompile::bn128::{
    pair::{BYZANTIUM_PAIR_BASE, BYZANTIUM_PAIR_PER_POINT},
    run_pair,
};

openvm::entry!(main);

openvm_algebra_moduli_setup::moduli_init! {
    "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47",
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001"
}

openvm_algebra_complex_macros::complex_init! {
    Fp2 { mod_idx = 0 },
}

pub fn main() {
    let input = read_vec();
    let expected = read_vec();

    let outcome = run_pair(
        &input,
        BYZANTIUM_PAIR_PER_POINT,
        BYZANTIUM_PAIR_BASE,
        260_000,
    )
    .unwrap();
    assert_eq!(outcome.bytes, expected);
}
