#![forbid(unsafe_code)]

pub const ID: &[u8] = b"kryvola/research/public-metadata/v1\0";
pub const CYCLES: u64 = 1_000_000;

/// Fixed public model/program/snapshot fields; no owner plaintext or FHE relation.
pub fn journal(fields: [[u8; 32]; 3], mode: u8) -> Option<Vec<u8>> {
    if mode != 1 {
        return None;
    }
    let mut bytes = ID.to_vec();
    bytes.extend([mode, 0]); // public-metadata mode, successful relation outcome
    bytes.extend(CYCLES.to_le_bytes());
    for field in fields {
        bytes.extend(field);
    }
    let commitment = blake3::hash(&bytes);
    bytes.extend(commitment.as_bytes());
    Some(bytes)
}
