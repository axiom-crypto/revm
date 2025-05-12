use k256::{
    ecdsa::{Error, RecoveryId, Signature},
    Secp256k1,
};
use openvm_ecc_guest::{algebra::IntMod, ecdsa::VerifyingKey, weierstrass::WeierstrassPoint};
use openvm_keccak256_guest::keccak256;
use revm_primitives::{alloy_primitives::B512, B256};

pub fn ecrecover(sig: &B512, mut recid: u8, msg: &B256) -> Result<B256, Error> {
    let _sig = sig;
    let _recid = recid;
    // parse signature
    let mut sig = Signature::from_slice(sig.as_slice())?;
    if let Some(sig_normalized) = sig.normalize_s() {
        sig = sig_normalized;
        recid ^= 1;
    }
    let recid = RecoveryId::from_byte(recid).expect("recovery ID is valid");

    // annoying: Signature::to_bytes copies from slice
    let recovered_key =
        VerifyingKey::<Secp256k1>::recover_from_prehash_noverify(&msg[..], &sig.to_bytes(), recid)?;
    let public_key = recovered_key.as_affine();
    let mut encoded = [0u8; 64];
    encoded[..32].copy_from_slice(&public_key.x().to_be_bytes());
    encoded[32..].copy_from_slice(&public_key.y().to_be_bytes());
    // hash it
    let mut hash = keccak256(&encoded);
    // truncate to 20 bytes
    hash[..12].fill(0);
    Ok(B256::from(hash))
}
