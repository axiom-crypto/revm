#![no_std]
#![no_main]

use openvm::io::read_vec;
use openvm_pairing_guest::bls12_381::Bls12_381G1Affine;
use revm_precompile::kzg_point_evaluation::{run, GAS_COST};

openvm::entry!(main);

openvm_algebra_guest::moduli_macros::moduli_init! {
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
}

openvm_algebra_guest::complex_macros::complex_init! {
    Bls12_381Fp2 { mod_idx = 0 },
}

openvm_ecc_guest::sw_macros::sw_init! {
    Bls12_381G1Affine
}

pub fn main() {
    setup_all_moduli();
    setup_all_complex_extensions();
    setup_all_curves();

    let input = read_vec();
    let expected_output = read_vec();

    let gas = GAS_COST;
    let output = run(&input.into(), gas, &Default::default()).unwrap();
    assert_eq!(output.gas_used, gas);
    assert_eq!(&output.bytes[..], &expected_output);
}
