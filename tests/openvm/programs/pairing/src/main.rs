#![no_std]
#![no_main]

use openvm::io::read_vec;
use revm_precompile::bn128::{
    pair::{BYZANTIUM_PAIR_BASE, BYZANTIUM_PAIR_PER_POINT},
    run_pair,
};

openvm::init!();

openvm::entry!(main);

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
