use std::{path::PathBuf, thread::Builder};

use openvm_build::GuestOptions;
use openvm_sdk::config::AppConfig;
use openvm_sdk::StdIn;
use openvm_sdk::{config::SdkVmConfig, Sdk};
use primitives::{hex, keccak256, Bytes, U256};
use secp256k1::{Message, SecretKey, SECP256K1};

#[test]
fn test_ecrecover_precompile() -> eyre::Result<()> {
    // Spawn thread with increased stack size
    let handle = Builder::new()
        .stack_size(4 * 1024 * 1024) // 4MB stack
        .spawn(|| -> eyre::Result<()> {
            let app_config: AppConfig<SdkVmConfig> =
                toml::from_str(include_str!("../programs/ecrecover/openvm.toml")).unwrap();
            let sdk = Sdk::new(app_config)?;
            let guest_opts = GuestOptions::default();
            let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
            pkg_dir.push("programs/ecrecover");

            let elf = sdk.build(guest_opts.clone(), &pkg_dir, &None, None)?;

            // Generate secp256k1 signature
            let data = hex::decode("1337133713371337").unwrap();
            let hash = keccak256(data);
            let secret_key = SecretKey::new(&mut rand::thread_rng());

            let message = Message::from_digest_slice(&hash[..]).unwrap();
            let s = SECP256K1.sign_ecdsa_recoverable(&message, &secret_key);
            let (rec_id, data) = s.serialize_compact();
            let rec_id = i32::from(rec_id) as u8 + 27;

            let mut message_and_signature = [0u8; 128];
            message_and_signature[0..32].copy_from_slice(&hash[..]);

            // Fit signature into format the precompile expects
            let rec_id = U256::from(rec_id as u64);
            message_and_signature[32..64].copy_from_slice(&rec_id.to_be_bytes::<32>());
            message_and_signature[64..128].copy_from_slice(&data);

            let message_and_signature = Bytes::from(message_and_signature);
            let public = SECP256K1.recover_ecdsa(&message, &s).unwrap();
            let mut expected = keccak256(&public.serialize_uncompressed()[1..]);
            expected[..12].fill(0);
            let mut stdin = StdIn::default();
            stdin.write_bytes(expected.as_slice());
            stdin.write_bytes(&message_and_signature);
            sdk.app_prover(elf)?.prove(stdin)?;
            Ok(())
        })?;

    handle.join().unwrap()
}
