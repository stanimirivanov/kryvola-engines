//! Worker-local, fixed FHE-Q1 CPU evaluation. No owner-key or decrypt API.
#![forbid(unsafe_code)]

use std::io::Cursor;
use tfhe::{
    CompressedServerKey, ConfigBuilder, FheUint8, FheUint8ConformanceParams,
    safe_serialization::{safe_deserialize_conformant, safe_serialize},
    shortint::parameters::v1_4::V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as PARAMETERS,
};

pub const KEY_MAX: usize = 64 << 20;
const CIPHERTEXT_MAX: usize = 1 << 20;
pub const PAIR_MAX: usize = 2 * (8 + CIPHERTEXT_MAX);

/// Public capability of this fixed CPU kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub profile: &'static str,
    pub assurance: &'static str,
    pub program_digest: &'static str,
    pub parameter_set_digest: &'static str,
}

pub const CAPABILITY: Capability = Capability {
    profile: "FHE-Q1",
    assurance: "CONFIDENTIALITY_ONLY",
    program_digest: "52687303e4a13081f0f40c15bfa0fafbf35812fb96a3d30f99206ee534c010f5",
    parameter_set_digest: "cda9e129d55cc6a17060d8913f6e0d554c5a990e62c967514db86bf57a524674",
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationError {
    Program,
    Size,
    Binding,
    Framing,
    Native,
}

impl EvaluationError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Program => "EVALUATOR_PROGRAM",
            Self::Size => "EVALUATOR_SIZE",
            Self::Binding => "EVALUATOR_BINDING",
            Self::Framing => "EVALUATOR_FRAMING",
            Self::Native => "EVALUATOR_NATIVE",
        }
    }
}

/// Expected commitments from an independently authorized task/artifact context.
/// Hashes supplied alongside hostile bytes do not establish that authorization.
#[derive(Clone, Copy)]
pub struct EvaluationBinding {
    pub evaluation_key_digest: [u8; 32],
    pub input_blob_digest: [u8; 32],
}

/// Spec full-blob commitment, shared framing with the owner library.
pub fn blob_digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new()
        .update(b"kryvola/blob/v1\0")
        .update(bytes)
        .finalize()
        .as_bytes()
}

/// Match the program digest from the independently authorized plan before decoding.
pub fn evaluate_program(
    program_digest: &str,
    binding: EvaluationBinding,
    key: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, EvaluationError> {
    if program_digest != CAPABILITY.program_digest {
        return Err(EvaluationError::Program);
    }
    evaluate(binding, key, input)
}

/// Evaluate the frozen uint8 modular circuit; no arbitrary program is accepted.
pub fn evaluate(
    binding: EvaluationBinding,
    key: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, EvaluationError> {
    if key.len() > KEY_MAX || input.len() > PAIR_MAX {
        return Err(EvaluationError::Size);
    }
    if blob_digest(key) != binding.evaluation_key_digest
        || blob_digest(input) != binding.input_blob_digest
    {
        return Err(EvaluationError::Binding);
    }
    let mut remainder = input;
    let a = decode(&mut remainder)?;
    let b = decode(&mut remainder)?;
    if !remainder.is_empty() {
        return Err(EvaluationError::Framing);
    }
    let config = ConfigBuilder::with_custom_parameters(PARAMETERS).build();
    let mut cursor = Cursor::new(key);
    let key: CompressedServerKey =
        safe_deserialize_conformant(&mut cursor, KEY_MAX as u64, &config.into())
            .map_err(|_| EvaluationError::Native)?;
    if cursor.position() != cursor.get_ref().len() as u64 {
        return Err(EvaluationError::Framing);
    }
    // All commitments, native shapes and complete framing pass before decompression.
    // TFHE's guard restores the caller's thread-local context, including on unwind.
    tfhe::with_server_key_as_context(key.decompress(), || {
        let output = [&a * 3u8 + &b * 5u8 + 7u8, &a * &b + 11u8];
        let mut result = Vec::new();
        for ciphertext in output {
            let mut encoded = Vec::new();
            safe_serialize(&ciphertext, &mut encoded, CIPHERTEXT_MAX as u64)
                .map_err(|_| EvaluationError::Native)?;
            result.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
            result.extend_from_slice(&encoded);
        }
        Ok(result)
    })
}

fn decode(input: &mut &[u8]) -> Result<FheUint8, EvaluationError> {
    let (length, rest) = input
        .split_first_chunk::<8>()
        .ok_or(EvaluationError::Framing)?;
    let length = u64::from_le_bytes(*length);
    if !(1..=CIPHERTEXT_MAX as u64).contains(&length) {
        return Err(EvaluationError::Size);
    }
    let (encoded, rest) = rest
        .split_at_checked(length as usize)
        .ok_or(EvaluationError::Framing)?;
    *input = rest;
    let mut cursor = Cursor::new(encoded);
    let ciphertext = safe_deserialize_conformant(
        &mut cursor,
        CIPHERTEXT_MAX as u64,
        &FheUint8ConformanceParams::from(PARAMETERS),
    )
    .map_err(|_| EvaluationError::Native)?;
    if cursor.position() != length {
        return Err(EvaluationError::Framing);
    }
    Ok(ciphertext)
}
