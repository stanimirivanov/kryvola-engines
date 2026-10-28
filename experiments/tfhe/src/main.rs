#![forbid(unsafe_code)]
#![deny(warnings)]

use std::fs::{self, File};
use std::io::{Cursor, Read};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tfhe::conformance::ParameterSetConformant;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize_conformant, safe_serialize};
use tfhe::shortint::parameters::v1_4::{
    V1_4_PARAM_MESSAGE_1_CARRY_1_KS_PBS_TUNIFORM_2M128 as OTHER_PARAMETERS,
    V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128 as PARAMETERS,
};
use tfhe::{
    ClientKey, CompressedServerKey, ConfigBuilder, FheUint8, FheUint8ConformanceParams, FheUint16,
};

type Result<T> = std::result::Result<T, i32>;
const HEADER: usize = 108;
const KEY_MAX: u64 = 64 << 20;
const CT_MAX: u64 = 1 << 20;
const EXPANSION_MAX: u64 = 1 << 30;
const MAGIC: &[u8; 8] = b"KRYTFH19";
const VERSION: &[u8; 8] = b"1.8.1\0\0\0";
const FRAMING: i32 = 20;
const VERSION_ERROR: i32 = 21;
const PROFILE: i32 = 22;
const DOMAIN: i32 = 23;
const COUNT: i32 = 24;
const SIZE: i32 = 25;
const BUDGET: i32 = 26;
const BINDING: i32 = 27;
const NATIVE: i32 = 28;
const TEST: i32 = 29;

macro_rules! encode {
    ($value:expr, $limit:expr) => {{
        let mut bytes = Vec::new();
        safe_serialize($value, &mut bytes, $limit).map_err(|_| NATIVE)?;
        bytes
    }};
}

fn need(condition: bool, code: i32) -> Result<()> {
    if condition { Ok(()) } else { Err(code) }
}

fn profile() -> blake3::Hash {
    blake3::hash(b"tfhe=1.8.1|crate=0d60dcde24115624e62a9a8dc627daa8d3dad40e8de69975957d12ee9ab70a2b|V1_4_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128")
}

fn reservation() -> u64 {
    // A policy reservation from the trusted shape, NOT a measured RSS bound.
    let p = PARAMETERS;
    let (lwe, glwe, poly) = (
        p.lwe_dimension.0 as u64,
        p.glwe_dimension.0 as u64,
        p.polynomial_size.0 as u64,
    );
    let bsk = lwe * (glwe + 1).pow(2) * poly * p.pbs_level.0 as u64 * 8;
    let ksk = glwe * poly * p.ks_level.0 as u64 * (lwe + 1) * 8;
    4 * (bsk + ksk) + CT_MAX
}

fn take<const N: usize>(input: &mut impl Read) -> Result<[u8; N]> {
    let mut value = [0; N];
    input.read_exact(&mut value).map_err(|_| FRAMING)?;
    Ok(value)
}

fn decode_ct(bytes: &[u8]) -> Result<FheUint8> {
    let mut cursor = Cursor::new(bytes);
    let value = safe_deserialize_conformant(
        &mut cursor,
        CT_MAX,
        &FheUint8ConformanceParams::from(PARAMETERS),
    )
    .map_err(|_| NATIVE)?;
    need(cursor.position() == bytes.len() as u64, NATIVE)?;
    Ok(value)
}

fn evaluator(root: &Path, context: blake3::Hash, approved_input: blake3::Hash) -> Result<()> {
    let mut input = File::open(root.join("input.bin")).map_err(|_| FRAMING)?;
    need(&take::<8>(&mut input)? == MAGIC, FRAMING)?;
    need(&take::<8>(&mut input)? == VERSION, VERSION_ERROR)?;
    need(take::<32>(&mut input)? == *profile().as_bytes(), PROFILE)?;
    need(take::<32>(&mut input)? == *context.as_bytes(), DOMAIN)?;
    let count = u32::from_le_bytes(take(&mut input)?);
    let key_len = u64::from_le_bytes(take(&mut input)?);
    let ct_len = u64::from_le_bytes(take(&mut input)?);
    let budget = u64::from_le_bytes(take(&mut input)?);
    need(count == 1, COUNT)?;
    need(
        key_len > 0 && key_len <= KEY_MAX && ct_len > 0 && ct_len <= CT_MAX,
        SIZE,
    )?;
    need(budget >= reservation() && budget <= EXPANSION_MAX, BUDGET)?;
    need(
        input.metadata().map_err(|_| FRAMING)?.len() == HEADER as u64 + key_len + ct_len,
        FRAMING,
    )?;
    let mut key = vec![0; key_len as usize];
    let mut ct = vec![0; ct_len as usize];
    input.read_exact(&mut key).map_err(|_| FRAMING)?;
    input.read_exact(&mut ct).map_err(|_| FRAMING)?;
    need(
        blake3::hash(&key) == context && blake3::hash(&ct) == approved_input,
        BINDING,
    )?;
    let config = ConfigBuilder::with_custom_parameters(PARAMETERS).build();
    let mut cursor = Cursor::new(key);
    let compressed: CompressedServerKey =
        safe_deserialize_conformant(&mut cursor, KEY_MAX, &config.into()).map_err(|_| NATIVE)?;
    need(cursor.position() == key_len, NATIVE)?;
    let value = decode_ct(&ct)?;
    // No decompression or evaluation until all shape/binding/budget checks pass.
    tfhe::set_server_key(compressed.decompress());
    let result = &value + 1u8;
    let encoded = encode!(&result, CT_MAX);
    fs::write(root.join("output.bin"), encoded).map_err(|_| FRAMING)?;
    Ok(())
}

fn packet(key: &[u8], ct: &[u8], context: blake3::Hash) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + key.len() + ct.len());
    bytes.extend(MAGIC);
    bytes.extend(VERSION);
    bytes.extend(profile().as_bytes());
    bytes.extend(context.as_bytes());
    bytes.extend(1u32.to_le_bytes());
    bytes.extend((key.len() as u64).to_le_bytes());
    bytes.extend((ct.len() as u64).to_le_bytes());
    bytes.extend(reservation().to_le_bytes());
    bytes.extend(key);
    bytes.extend(ct);
    bytes
}

fn dispatch(
    root: &Path,
    bytes: &[u8],
    context: blake3::Hash,
    approved: blake3::Hash,
    expected: i32,
) -> Result<()> {
    fs::write(root.join("input.bin"), bytes).map_err(|_| FRAMING)?;
    let mut child = Command::new(std::env::current_exe().map_err(|_| TEST)?)
        .arg("evaluator")
        .arg(root)
        .arg(context.to_hex().as_str())
        .arg(approved.to_hex().as_str())
        .env_clear()
        .env("RAYON_NUM_THREADS", "2")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| TEST)?;
    need(child.id() != std::process::id(), TEST)?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|_| TEST)? {
            return need(status.code() == Some(expected), TEST);
        }
        if start.elapsed() > Duration::from_secs(90) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(TEST);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn owner(root: &Path) -> Result<()> {
    need(reservation() <= EXPANSION_MAX, BUDGET)?;
    let config = ConfigBuilder::with_custom_parameters(PARAMETERS).build();
    let client_key = ClientKey::generate(config);
    let key = encode!(&CompressedServerKey::new(&client_key), KEY_MAX);
    let ciphertext = FheUint8::encrypt(41u8, &client_key);
    let ct = encode!(&ciphertext, CT_MAX);
    let (context, approved) = (blake3::hash(&key), blake3::hash(&ct));
    let valid = packet(&key, &ct, context);
    dispatch(root, &valid, context, approved, 0)?;
    let output = File::open(root.join("output.bin")).map_err(|_| TEST)?;
    need(output.metadata().map_err(|_| TEST)?.len() <= CT_MAX, SIZE)?;
    let mut result = Vec::new();
    output
        .take(CT_MAX + 1)
        .read_to_end(&mut result)
        .map_err(|_| TEST)?;
    let plain: u8 = decode_ct(&result)?.decrypt(&client_key);
    need(plain == 42, TEST)?;

    let mut negatives = 0;
    // Header-only failures must occur before allocation or native decoding.
    for (offset, replacement, code) in [
        (8, vec![b'9'], VERSION_ERROR),
        (16, vec![0; 32], PROFILE),
        (48, vec![0; 32], DOMAIN),
        (80, 0u32.to_le_bytes().to_vec(), COUNT),
        (80, u32::MAX.to_le_bytes().to_vec(), COUNT),
        (84, (KEY_MAX + 1).to_le_bytes().to_vec(), SIZE),
        (92, (CT_MAX + 1).to_le_bytes().to_vec(), SIZE),
        (100, (reservation() - 1).to_le_bytes().to_vec(), BUDGET),
    ] {
        let mut header = valid[..HEADER].to_vec();
        header[offset..offset + replacement.len()].copy_from_slice(&replacement);
        dispatch(root, &header, context, approved, code)?;
        negatives += 1;
    }
    dispatch(root, &valid[..valid.len() - 1], context, approved, FRAMING)?;
    negatives += 1;
    // Approved corrupt/type-mismatched bytes exercise native validation, not just hashes.
    let wide = FheUint16::encrypt(41u16, &client_key);
    let wrong_type = encode!(&wide, CT_MAX);
    let (blocks, _, _, _) = wide.into_raw_parts();
    let (_, id, tag, metadata) = ciphertext.clone().into_raw_parts();
    let wrong_blocks = encode!(&FheUint8::from_raw_parts(blocks, id, tag, metadata), CT_MAX);
    let mut trailing = ct.clone();
    trailing.push(0);
    let mut wrong_version = ct.clone();
    wrong_version[8] ^= 1; // Mutate a header-version character, never a length/allocation field.
    for bad in [
        ct[..ct.len() - 1].to_vec(),
        wrong_version,
        wrong_type,
        wrong_blocks,
        trailing,
    ] {
        dispatch(
            root,
            &packet(&key, &bad, context),
            context,
            blake3::hash(&bad),
            NATIVE,
        )?;
        negatives += 1;
    }
    let wrong_config = ConfigBuilder::with_custom_parameters(OTHER_PARAMETERS).build();
    let wrong_key = ClientKey::generate(wrong_config);
    let wrong_params = encode!(&FheUint8::encrypt(41u8, &wrong_key), CT_MAX);
    dispatch(
        root,
        &packet(&key, &wrong_params, context),
        context,
        blake3::hash(&wrong_params),
        NATIVE,
    )?;
    negatives += 1;
    // Native conformance deliberately cannot detect same-parameter foreign keys.
    let other_owner = ClientKey::generate(config);
    let foreign = FheUint8::encrypt(41u8, &other_owner);
    need(
        foreign.is_conformant(&FheUint8ConformanceParams::from(PARAMETERS)),
        TEST,
    )?;
    let foreign = encode!(&foreign, CT_MAX);
    dispatch(
        root,
        &packet(&key, &foreign, context),
        context,
        approved,
        BINDING,
    )?;
    negatives += 1;
    println!(
        "{{\"experiment\":\"tfhe-codec\",\"passed\":true,\"process_separated\":true,\"negative_cases\":{negatives},\"foreign_key_native_conformant\":true,\"reservation_is_estimate\":true,\"reservation_bytes\":{},\"serialized_key_bytes\":{},\"serialized_ciphertext_bytes\":{}}}",
        reservation(),
        key.len(),
        ct.len()
    );
    Ok(())
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    let root = args.get(2).ok_or(TEST).map(Path::new)?;
    match args.get(1).and_then(|v| v.to_str()) {
        Some("owner") if args.len() == 3 => owner(root),
        Some("evaluator") if args.len() == 5 => {
            let context =
                blake3::Hash::from_hex(args[3].to_str().ok_or(TEST)?).map_err(|_| TEST)?;
            let approved =
                blake3::Hash::from_hex(args[4].to_str().ok_or(TEST)?).map_err(|_| TEST)?;
            evaluator(root, context, approved)
        }
        _ => Err(TEST),
    }
}

fn main() {
    std::panic::set_hook(Box::new(|_| eprintln!("TFHE_EXPERIMENT_PANIC")));
    if let Err(code) = run() {
        eprintln!("TFHE_EXPERIMENT_REJECTED");
        std::process::exit(code);
    }
}
