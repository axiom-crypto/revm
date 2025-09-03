#![no_std]
#![no_main]

use openvm::io::read_vec;
#[allow(unused_imports)]
use openvm_pairing::bls12_381::Bls12_381G1Affine;
use revm_precompile::kzg_point_evaluation::{run, GAS_COST};

openvm::entry!(main);

#[cfg(feature = "use-intrinsics")]
openvm::init!();

pub fn main() {
    let input = read_vec();
    let expected_output = read_vec();

    let gas = GAS_COST;
    let output = run(&input, gas).unwrap();
    assert_eq!(output.gas_used, gas);
    assert_eq!(&output.bytes[..], &expected_output);
}
