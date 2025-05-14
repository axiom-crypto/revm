use std::path::PathBuf;

use num_bigint::BigUint;
use num_traits::{FromPrimitive, Zero};
use openvm_algebra_circuit::{Fp2Extension, ModularExtension};
use openvm_build::GuestOptions;
use openvm_circuit::utils::air_test_with_min_segments;
use openvm_ecc_circuit::{CurveConfig, WeierstrassExtension};
use openvm_pairing_circuit::{PairingCurve, PairingExtension};
use openvm_pairing_guest::bls12_381::{BLS12_381_MODULUS, BLS12_381_ORDER};
use openvm_sdk::StdIn;
use openvm_sdk::{config::SdkVmConfig, Sdk};
use primitives::eip4844::VERSIONED_HASH_VERSION_KZG;
use primitives::hex;
use sha2::{Digest, Sha256};

// These tests should be run with --profile=fast or --profile=ethtests for more compiler optimization

#[test]
fn test_kzg_precompile_with_intrinsics() {
    let sdk = Sdk::new();
    let guest_opts = GuestOptions::default().with_features(["use-intrinsics"]);
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    pkg_dir.push("programs/kzg_point_evaluation");
    let elf = sdk.build(guest_opts, &pkg_dir, &None).unwrap();

    let vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .keccak(Default::default())
        .modular(ModularExtension::new(vec![
            BLS12_381_MODULUS.clone(),
            BLS12_381_ORDER.clone(),
        ]))
        .ecc(WeierstrassExtension::new(vec![CurveConfig {
            modulus: BLS12_381_MODULUS.clone(),
            scalar: BLS12_381_ORDER.clone(),
            a: BigUint::zero(),
            b: BigUint::from_u8(4).unwrap(),
        }]))
        .fp2(Fp2Extension::new(vec![BLS12_381_MODULUS.clone()]))
        .pairing(PairingExtension::new(vec![PairingCurve::Bls12_381]))
        .build();
    let exe = sdk.transpile(elf, vm_config.transpiler()).unwrap();

    // test data from: https://github.com/ethereum/c-kzg-4844/blob/main/tests/verify_kzg_proof/kzg-mainnet/verify_kzg_proof_case_correct_proof_31ebd010e6098750/data.yaml

    let commitment = hex!("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7").to_vec();
    let mut versioned_hash = Sha256::digest(&commitment).to_vec();
    versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
    let z = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000").to_vec();
    let y = hex!("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9").to_vec();
    let proof = hex!("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c").to_vec();

    let input = [versioned_hash, z, y, commitment, proof].concat();

    let expected_output = hex!("000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

    let mut io = StdIn::default();
    io.write_bytes(&input);
    io.write_bytes(&expected_output);
    air_test_with_min_segments(vm_config, exe, io, 1);
}

#[test]
#[ignore]
fn test_kzg_precompile_without_intrinsics() {
    let sdk = Sdk::new();
    let guest_opts = GuestOptions::default();
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    pkg_dir.push("programs/kzg_point_evaluation");
    let elf = sdk.build(guest_opts, &pkg_dir, &None).unwrap();

    let vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .keccak(Default::default())
        .build();
    let exe = sdk.transpile(elf, vm_config.transpiler()).unwrap();

    // test data from: https://github.com/ethereum/c-kzg-4844/blob/main/tests/verify_kzg_proof/kzg-mainnet/verify_kzg_proof_case_correct_proof_31ebd010e6098750/data.yaml
    let commitment = hex!("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7").to_vec();
    let mut versioned_hash = Sha256::digest(&commitment).to_vec();
    versioned_hash[0] = VERSIONED_HASH_VERSION_KZG;
    let z = hex!("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000").to_vec();
    let y = hex!("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9").to_vec();
    let proof = hex!("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c").to_vec();

    let input = [versioned_hash, z, y, commitment, proof].concat();

    let expected_output = hex!("000000000000000000000000000000000000000000000000000000000000100073eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");

    let mut io = StdIn::default();
    io.write_bytes(&input);
    io.write_bytes(&expected_output);
    air_test_with_min_segments(vm_config, exe, io, 1);
}
