//! Collection of sigma proofs (more precisely, "arguments") that are used in the Solana zk-token
//! protocol.
//!
//! The module contains implementations of the following proof systems that work on Pedersen
//! commitments and twisted ElGamal ciphertexts:
//! - Equality proof: can be used to certify that a twisted ElGamal ciphertext encrypts the same
//! message as either a Pedersen commitment or another ElGamal ciphertext.
//! - Validity proof: can be used to certify that a twisted ElGamal ciphertext is a properly-formed
//! ciphertext with respect to a pair of ElGamal public keys.
//! - Zero-balance proof: can be used to certify that a twisted ElGamal ciphertext encrypts the
//! message 0.
//! - Fee proof: can be used to certify that an ElGamal ciphertext properly encrypts a transfer
//! fee.
//!
//! We refer to the zk-token paper for the formal details and security proofs of these argument
//! systems.

pub mod batched_grouped_ciphertext_validity_proof;
pub mod ciphertext_ciphertext_equality_proof;
pub mod ciphertext_commitment_equality_proof;
pub mod errors;
pub mod fee_proof;
pub mod grouped_ciphertext_validity_proof;
pub mod pubkey_proof;
pub mod zero_balance_proof;

#[cfg(not(target_os = "solana"))]
use {
    crate::errors::ProofVerificationError,
    curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar},
};

/// Deserializes an optional slice of bytes to a compressed Ristretto point.
///
/// This is a helper function for deserializing byte encodings of sigma proofs. It is designed to
/// be used with `std::slice::Chunks`.
#[cfg(not(target_os = "solana"))]
fn ristretto_point_from_optional_slice(
    optional_slice: Option<&[u8]>,
) -> Result<CompressedRistretto, ProofVerificationError> {
    let slice = optional_slice.ok_or(ProofVerificationError::Deserialization)?;
    let point_bytes = slice[..32]
        .try_into()
        .map_err(|_| ProofVerificationError::Deserialization)?;

    Ok(CompressedRistretto::from_slice(point_bytes))
}

/// Deserializes an optional slice of bytes to a scalar.
///
/// This is a helper function for deserializing byte encodings of sigma proofs. It is designed to
/// be used with `std::slice::Chunks`.
#[cfg(not(target_os = "solana"))]
fn canonical_scalar_from_optional_slice(
    optional_slice: Option<&[u8]>,
) -> Result<Scalar, ProofVerificationError> {
    let slice = optional_slice.ok_or(ProofVerificationError::Deserialization)?;
    let scalar_bytes = slice[..32]
        .try_into()
        .map_err(|_| ProofVerificationError::Deserialization)?;

    let scalar = Scalar::from_canonical_bytes(scalar_bytes)
        .ok_or(ProofVerificationError::Deserialization)?;
    Ok(scalar)
}
