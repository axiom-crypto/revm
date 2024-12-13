use std::path::PathBuf;

use num_bigint_dig::BigUint;
use num_traits::{FromPrimitive, Zero};
use openvm_algebra_circuit::{Fp2Extension, ModularExtension};
use openvm_algebra_transpiler::{Fp2TranspilerExtension, ModularTranspilerExtension};
use openvm_build::{GuestOptions, TargetFilter};
use openvm_circuit::arch::SystemConfig;
use openvm_circuit::utils::new_air_test_with_min_segments;
use openvm_ecc_circuit::{CurveConfig, WeierstrassExtension};
use openvm_ecc_transpiler::EccTranspilerExtension;
use openvm_pairing_circuit::{PairingCurve, PairingExtension, Rv32PairingConfig};
use openvm_pairing_guest::bn254::{BN254_MODULUS, BN254_ORDER};
use openvm_pairing_transpiler::PairingTranspilerExtension;
use openvm_rv32im_transpiler::{
    Rv32ITranspilerExtension, Rv32IoTranspilerExtension, Rv32MTranspilerExtension,
};
use openvm_sdk::Sdk;
use openvm_stark_sdk::openvm_stark_backend::p3_field::AbstractField;
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use openvm_transpiler::transpiler::Transpiler;
use primitives::hex;

type F = BabyBear;

#[test]
fn test_ec_pairing_precompile() {
    let sdk = Sdk;
    let guest_opts = GuestOptions::default();
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    pkg_dir.push("../program");
    let ec_precompile = sdk
        .build(guest_opts.clone(), &pkg_dir, &TargetFilter::default())
        .unwrap();

    let transpiler = Transpiler::<F>::default()
        .with_extension(Rv32ITranspilerExtension)
        .with_extension(Rv32MTranspilerExtension)
        .with_extension(Rv32IoTranspilerExtension)
        .with_extension(PairingTranspilerExtension)
        .with_extension(ModularTranspilerExtension)
        .with_extension(EccTranspilerExtension)
        .with_extension(Fp2TranspilerExtension);
    let exe = sdk.transpile(ec_precompile, transpiler).unwrap();

    // Config
    let config = Rv32PairingConfig {
        system: SystemConfig::default().with_continuations(),
        base: Default::default(),
        mul: Default::default(),
        io: Default::default(),
        modular: ModularExtension::new(vec![BN254_MODULUS.clone()]),
        fp2: Fp2Extension::new(vec![BN254_MODULUS.clone()]),
        weierstrass: WeierstrassExtension::new(vec![CurveConfig {
            modulus: BN254_MODULUS.clone(),
            scalar: BN254_ORDER.clone(),
            a: BigUint::zero(),
            b: BigUint::from_u8(3u8).unwrap(),
        }]),
        pairing: PairingExtension::new(vec![PairingCurve::Bn254]),
    };

    let input = hex::decode(
        "\
        1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f59\
        3034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41\
        209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf7\
        04bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a41678\
        2bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d\
        120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550\
        111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c\
        2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411\
        198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2\
        1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed\
        090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b\
        12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
    )
    .unwrap();
    let expected =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();

    let io = [input, expected]
        .into_iter()
        .map(|w| w.into_iter().map(F::from_canonical_u8).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    new_air_test_with_min_segments(config, exe, io, 1, false);
}
