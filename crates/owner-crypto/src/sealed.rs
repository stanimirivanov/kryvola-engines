//! Owner-local authenticated persistence for the pinned native key codec.
use ring::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use tfhe::safe_serialization::{safe_deserialize, safe_serialized_size};
use zeroize::Zeroizing;

use super::*;

const MAGIC: &[u8; 8] = b"KRYQ1K\0\x01";
const CLIENT_MAX: usize = 1 << 20;
const HEADER: usize = MAGIC.len() + 12;
const TAG: usize = 16;
const LENGTH: usize = 4;
const SEALED_MAX: usize = HEADER + LENGTH + CLIENT_MAX + KEY_MAX as usize + TAG;

fn cipher(wrapping_key: &[u8; 32]) -> Result<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, wrapping_key)
        .map(LessSafeKey::new)
        .map_err(|_| OwnerError::Native)
}

fn associated_data(context: &[u8; 32]) -> Aad<[u8; 40]> {
    let mut bytes = [0; 40];
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    bytes[MAGIC.len()..].copy_from_slice(context);
    Aad::from(bytes)
}

impl OwnerKey {
    /// Seal this opaque key under an independent high-entropy wrapping key and
    /// an application-supplied custody context commitment.
    pub fn seal(&self, wrapping_key: &[u8; 32], context: &[u8; 32]) -> Result<Vec<u8>> {
        let length = safe_serialized_size(&self.client).map_err(|_| OwnerError::Native)?;
        if !(1..=CLIENT_MAX as u64).contains(&length)
            || !(1..=KEY_MAX as usize).contains(&self.evaluation.len())
        {
            return Err(OwnerError::Size);
        }
        let length = length as usize;
        let mut payload = Zeroizing::new(vec![0; LENGTH + length + self.evaluation.len()]);
        payload[..LENGTH].copy_from_slice(&(length as u32).to_le_bytes());
        let mut target = &mut payload[LENGTH..LENGTH + length];
        safe_serialize(&self.client, &mut target, length as u64).map_err(|_| OwnerError::Native)?;
        if !target.is_empty() {
            return Err(OwnerError::Native);
        }
        payload[LENGTH + length..].copy_from_slice(&self.evaluation);
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| OwnerError::Native)?;
        let tag = cipher(wrapping_key)?
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                associated_data(context),
                &mut payload,
            )
            .map_err(|_| OwnerError::Native)?;
        let mut sealed = Vec::with_capacity(HEADER + payload.len() + TAG);
        sealed.extend_from_slice(MAGIC);
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&payload);
        sealed.extend_from_slice(tag.as_ref());
        Ok(sealed)
    }

    /// Authenticate a bounded envelope before parsing any native key material.
    pub fn restore(wrapping_key: &[u8; 32], context: &[u8; 32], sealed: &[u8]) -> Result<Self> {
        if !(HEADER + LENGTH + 2 + TAG..=SEALED_MAX).contains(&sealed.len()) {
            return Err(OwnerError::Size);
        }
        let (header, encrypted) = sealed.split_at(HEADER);
        let nonce = header.strip_prefix(MAGIC).ok_or(OwnerError::Framing)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| OwnerError::Framing)?;
        let mut storage = Zeroizing::new(encrypted.to_vec());
        let payload = cipher(wrapping_key)?
            .open_in_place(nonce, associated_data(context), &mut storage)
            .map_err(|_| OwnerError::Binding)?;
        let (length, native) = payload
            .split_first_chunk::<LENGTH>()
            .ok_or(OwnerError::Framing)?;
        let length = u32::from_le_bytes(*length) as usize;
        let (client, evaluation) = native.split_at_checked(length).ok_or(OwnerError::Framing)?;
        if !(1..=CLIENT_MAX).contains(&length)
            || !(1..=KEY_MAX as usize).contains(&evaluation.len())
        {
            return Err(OwnerError::Size);
        }
        let mut input = Cursor::new(client);
        let client: ClientKey =
            safe_deserialize(&mut input, CLIENT_MAX as u64).map_err(|_| OwnerError::Native)?;
        if input.position() != length as u64 || client.computation_parameters() != PARAMETERS.into()
        {
            return Err(OwnerError::Native);
        }
        let mut input = Cursor::new(evaluation);
        let config = ConfigBuilder::with_custom_parameters(PARAMETERS).build();
        let _: CompressedServerKey =
            safe_deserialize_conformant(&mut input, KEY_MAX, &config.into())
                .map_err(|_| OwnerError::Native)?;
        if input.position() != evaluation.len() as u64 {
            return Err(OwnerError::Framing);
        }
        Ok(Self {
            client,
            evaluation: evaluation.to_vec(),
            evaluation_digest: blob_digest(evaluation),
        })
    }
}
