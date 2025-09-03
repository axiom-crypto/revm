use std::path::PathBuf;

use openvm_build::GuestOptions;
use openvm_sdk::config::AppConfig;
use openvm_sdk::{config::SdkVmConfig, Sdk};
use openvm_stark_sdk::openvm_stark_backend::p3_field::FieldAlgebra;
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use primitives::hex;

type F = BabyBear;

// These tests should be run with --profile=ethtests for more compiler optimization

// RUST_MIN_STACK=8388608
#[test]
fn test_ec_pairing_precompile() -> eyre::Result<()> {
    let app_config: AppConfig<SdkVmConfig> =
        toml::from_str(include_str!("../programs/pairing/openvm.toml")).unwrap();
    let sdk = Sdk::new(app_config)?;
    let guest_opts = GuestOptions::default();
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    pkg_dir.push("programs/pairing");
    let elf = sdk.build(guest_opts.clone(), &pkg_dir, &None, None)?;

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
    sdk.app_prover(elf)?.prove(io.into())?;
    Ok(())
}

#[test]
fn test_ec_add_precompile() -> eyre::Result<()> {
    let app_config: AppConfig<SdkVmConfig> =
        toml::from_str(include_str!("../programs/ec_add/openvm.toml")).unwrap();
    let sdk = Sdk::new(app_config)?;
    let guest_opts = GuestOptions::default();
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    pkg_dir.push("programs/ec_add");

    let elf = sdk.build(guest_opts.clone(), &pkg_dir, &None, None)?;

    let input = hex::decode(
        "\
         18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9\
         063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266\
         07c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed\
         06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7",
    )?;
    let expected = hex::decode(
        "\
        2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703\
        301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915",
    )?;

    let io = [input, expected]
        .into_iter()
        .map(|w| w.into_iter().map(F::from_canonical_u8).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    sdk.app_prover(elf)?.prove(io.into())?;
    Ok(())
}

#[test]
fn test_ec_mul_precompile() -> eyre::Result<()> {
    let app_config: AppConfig<SdkVmConfig> =
        toml::from_str(include_str!("../programs/ec_mul/openvm.toml")).unwrap();
    let sdk = Sdk::new(app_config)?;
    let guest_opts = GuestOptions::default();
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    pkg_dir.push("programs/ec_mul");
    let elf = sdk.build(guest_opts.clone(), &pkg_dir, &None, None)?;

    let input = hex::decode(
        "\
        2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb7\
        21611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204\
        00000000000000000000000000000000000000000000000011138ce750fa15c2",
    )
    .unwrap();
    let expected = hex::decode(
        "\
        070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c\
        031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc",
    )
    .unwrap();

    let io = [input, expected]
        .into_iter()
        .map(|w| w.into_iter().map(F::from_canonical_u8).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    sdk.app_prover(elf)?.prove(io.into())?;
    Ok(())
}
