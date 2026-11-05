//! Owner-local TFHE primitives for the pinned FHE-Q1 CPU research profile.
#![forbid(unsafe_code)]

use std::io::Cursor;
use tfhe::{
    ClientKey, CompressedServerKey, ConfigBuilder, FheUint8, FheUint8ConformanceParams,
    prelude::*,
    safe_serialization::{safe_deserialize_conformant, safe_serialize},
    shortint::parameters::v1_4::V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as PARAMETERS,
};

const CIPHERTEXT_MAX: usize = 1 << 20;
const KEY_MAX: u64 = 64 << 20;
const PAIR_MAX: usize = 2 * (8 + CIPHERTEXT_MAX);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerError {
    Size,
    Binding,
    Framing,
    Native,
}

type Result<T> = std::result::Result<T, OwnerError>;

/// Opaque process-local client key. Only evaluation material is exportable.
pub struct OwnerKey {
    client: ClientKey,
    evaluation: Vec<u8>,
    evaluation_digest: [u8; 32],
}

/// Expected digests from independently verified owner authorization.
/// A digest supplied alongside untrusted ciphertext is not authorization.
#[derive(Clone, Copy)]
pub struct OpenBinding {
    pub evaluation_key_digest: [u8; 32],
    pub result_blob_digest: [u8; 32],
}

/// Spec full-blob commitment for native artifact bytes.
pub fn blob_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(b"kryvola/blob/v1\0")
        .update(bytes)
        .finalize()
        .as_bytes()
}

impl OwnerKey {
    pub fn generate() -> Result<Self> {
        let config = ConfigBuilder::with_custom_parameters(PARAMETERS).build();
        let client = ClientKey::generate(config);
        let mut evaluation = Vec::new();
        safe_serialize(&CompressedServerKey::new(&client), &mut evaluation, KEY_MAX)
            .map_err(|_| OwnerError::Native)?;
        let evaluation_digest = blob_digest(&evaluation);
        Ok(Self {
            client,
            evaluation,
            evaluation_digest,
        })
    }

    pub fn evaluation_key(&self) -> &[u8] {
        &self.evaluation
    }

    /// Encrypt exactly two uint8 values using the frozen circuit's pair framing.
    pub fn encrypt_pair(&self, values: [u8; 2]) -> Result<Vec<u8>> {
        let mut pair = Vec::new();
        for value in values {
            let ciphertext =
                FheUint8::try_encrypt(value, &self.client).map_err(|_| OwnerError::Native)?;
            let mut encoded = Vec::new();
            safe_serialize(&ciphertext, &mut encoded, CIPHERTEXT_MAX as u64)
                .map_err(|_| OwnerError::Native)?;
            pair.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
            pair.extend_from_slice(&encoded);
        }
        Ok(pair)
    }

    pub fn open_result(&self, binding: OpenBinding, bytes: &[u8]) -> Result<[u8; 2]> {
        if bytes.len() > PAIR_MAX {
            return Err(OwnerError::Size);
        }
        if binding.evaluation_key_digest != self.evaluation_digest
            || binding.result_blob_digest != blob_digest(bytes)
        {
            return Err(OwnerError::Binding);
        }
        let mut remainder = bytes;
        let first = decode_next(&mut remainder)?;
        let second = decode_next(&mut remainder)?;
        if !remainder.is_empty() {
            return Err(OwnerError::Framing);
        }
        Ok([first.decrypt(&self.client), second.decrypt(&self.client)])
    }
}

fn decode_next(input: &mut &[u8]) -> Result<FheUint8> {
    let (length, rest) = input.split_first_chunk::<8>().ok_or(OwnerError::Framing)?;
    let length = u64::from_le_bytes(*length);
    if !(1..=CIPHERTEXT_MAX as u64).contains(&length) {
        return Err(OwnerError::Size);
    }
    let (encoded, rest) = rest
        .split_at_checked(length as usize)
        .ok_or(OwnerError::Framing)?;
    *input = rest;
    let mut cursor = Cursor::new(encoded);
    let ciphertext = safe_deserialize_conformant(
        &mut cursor,
        CIPHERTEXT_MAX as u64,
        &FheUint8ConformanceParams::from(PARAMETERS),
    )
    .map_err(|_| OwnerError::Native)?;
    if cursor.position() != length {
        return Err(OwnerError::Framing);
    }
    Ok(ciphertext)
}
