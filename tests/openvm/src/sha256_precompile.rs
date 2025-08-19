use std::path::PathBuf;

use openvm_build::GuestOptions;
use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    Sdk,
};
use openvm_stark_sdk::openvm_stark_backend::p3_field::FieldAlgebra;
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use primitives::hex;

type F = BabyBear;

#[test]
fn test_sha256_precompile() -> eyre::Result<()> {
    let app_config: AppConfig<SdkVmConfig> =
        toml::from_str(include_str!("../programs/sha256/openvm.toml"))?;
    let sdk = Sdk::new(app_config)?;
    let guest_opts = GuestOptions::default();
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    pkg_dir.push("programs/sha256");
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
    let expected = hex::decode("5f4e768d9faaf07a8c7264b937d60ff0b2fd52458e60a235f79c54bea68979dc")?;

    let io = [input, expected]
        .into_iter()
        .map(|w| w.into_iter().map(F::from_canonical_u8).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    sdk.app_prover(elf)?.prove(io.into())?;
    Ok(())
}
