#![no_std]
#![no_main]

extern crate alloc;

use openvm::io::read_vec;
use revm_precompile::hash::sha256_run;
openvm::entry!(main);

pub fn main() {
    let input = read_vec();
    let expected = read_vec();

    let outcome = sha256_run(&input, 260_000).unwrap();
    assert_eq!(outcome.bytes, expected);
}
