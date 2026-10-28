//! Local two-u8 ZKV2 compact-PKE experiment, never an inference-correctness proof.
use super::*;
use tfhe::conformance::ListSizeConstraint;
use tfhe::core_crypto::prelude::LweCiphertextCount;
use tfhe::integer::ciphertext::IntegerProvenCompactCiphertextListConformanceParams;
use tfhe::shortint::parameters::v1_4::{
    V1_4_PARAM_KEYSWITCH_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2 as CAST,
    V1_4_PARAM_PKE_TO_SMALL_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128_ZKV2 as PKE,
};
use tfhe::zk::{CompactPkeCrs, ZkComputeLoad, new_compact_pke_crs_conformance_params};
use tfhe::{
    CompactCiphertextList, CompactCiphertextListConformanceParams, CompactPublicKey,
    ProvenCompactCiphertextList,
};

const PROOF_MAX: u64 = 8 << 20;
const SETUP: [(&str, u64); 4] = [
    ("server.bin", KEY_MAX),
    ("crs.bin", 32 << 20),
    ("public.bin", CT_MAX),
    ("foreign.bin", CT_MAX),
];

macro_rules! decode {
    ($raw:expr, $limit:expr, $params:expr, $ty:ty) => {{
        let raw = $raw;
        let mut cursor = Cursor::new(raw);
        let value: $ty =
            safe_deserialize_conformant(&mut cursor, $limit, $params).map_err(|_| NATIVE)?;
        need(cursor.position() == raw.len() as u64, NATIVE)?;
        value
    }};
}

fn config() -> tfhe::Config {
    ConfigBuilder::with_custom_parameters(PARAMETERS)
        .use_dedicated_compact_public_key_parameters((PKE, CAST))
        .build()
}

fn read(root: &Path, name: &str, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(root.join(name))
        .map_err(|_| FRAMING)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| FRAMING)?;
    need(!bytes.is_empty() && bytes.len() as u64 <= maximum, SIZE)?;
    Ok(bytes)
}

fn admit(count: usize, budget: u64) -> Result<()> {
    need(count == 2, COUNT)?;
    need(budget == EXPANSION_MAX, BUDGET)
}

fn context(setup: &[Vec<u8>]) -> blake3::Hash {
    let mut hash = blake3::Hasher::new_derive_key("kryvola/research/compact-pke-v2/two-u8");
    hash.update(profile().as_bytes());
    hash.update(b"V1_4_PKE_TO_SMALL_ZKV2|V1_4_KEYSWITCH_PKE_TO_SMALL_ZKV2|crs_bits=16");
    for bytes in setup {
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hash.finalize()
}

fn proven(raw: &[u8], crs: &CompactPkeCrs) -> Result<ProvenCompactCiphertextList> {
    let parameters =
        IntegerProvenCompactCiphertextListConformanceParams::from_crs_and_parameters(PKE, crs);
    Ok(decode!(
        raw,
        PROOF_MAX,
        &parameters,
        ProvenCompactCiphertextList
    ))
}

pub(super) fn verifier(root: &Path, approved: blake3::Hash) -> Result<()> {
    let header = read(root, "request.bin", 44)?;
    need(header.len() == 44, FRAMING)?;
    let mut cursor = Cursor::new(&header);
    admit(
        u32::from_le_bytes(take(&mut cursor)?) as usize,
        u64::from_le_bytes(take(&mut cursor)?),
    )?;
    need(take::<32>(&mut cursor)? == *approved.as_bytes(), DOMAIN)?;
    let setup = SETUP
        .iter()
        .map(|(name, max)| read(root, name, *max))
        .collect::<Result<Vec<_>>>()?;
    need(context(&setup) == approved, BINDING)?;
    let crs_params =
        new_compact_pke_crs_conformance_params(PKE, LweCiphertextCount(4)).map_err(|_| PROFILE)?;
    let crs = decode!(setup[1].as_slice(), 32 << 20, &crs_params, CompactPkeCrs);
    let public = decode!(setup[2].as_slice(), CT_MAX, &PKE, CompactPublicKey);
    let foreign = decode!(setup[3].as_slice(), CT_MAX, &PKE, CompactPublicKey);
    let compact_bytes = read(root, "compact.bin", CT_MAX)?;
    let parameters = CompactCiphertextListConformanceParams::from_parameters_and_size_constraint(
        PKE,
        ListSizeConstraint::exact_size(2),
    );
    let compact = decode!(
        compact_bytes.as_slice(),
        CT_MAX,
        &parameters,
        CompactCiphertextList
    );
    need(
        (0..2).all(|index| compact.get_kind_of(index) == Some(tfhe::FheTypes::Uint8)),
        PROFILE,
    )?;
    let proof_bytes = read(root, "proof.bin", PROOF_MAX)?;
    let proof = proven(&proof_bytes, &crs)?;
    admit(proof.len(), EXPANSION_MAX)?;
    need(
        proof.get_kind_of(0) == Some(tfhe::FheTypes::Uint8)
            && proof.get_kind_of(1) == Some(tfhe::FheTypes::Uint8),
        PROFILE,
    )?;
    let start = Instant::now();
    need(
        proof.verify(&crs, &public, approved.as_bytes()).is_valid(),
        BINDING,
    )?;
    let verify_ns = start.elapsed().as_nanos();
    // These test the proof relation itself, not just an outer hash mismatch.
    need(
        proof.verify(&crs, &public, b"wrong-context").is_invalid(),
        TEST,
    )?;
    need(
        proof
            .verify(&crs, &foreign, approved.as_bytes())
            .is_invalid(),
        TEST,
    )?;
    need(
        proven(&proof_bytes[..proof_bytes.len() - 1], &crs).is_err(),
        TEST,
    )?;
    let mut trailing = proof_bytes.clone();
    trailing.push(0);
    need(proven(&trailing, &crs).is_err(), TEST)?;
    need(admit(3, EXPANSION_MAX) == Err(COUNT), TEST)?;
    need(admit(2, EXPANSION_MAX - 1) == Err(BUDGET), TEST)?;
    let key = decode!(
        setup[0].as_slice(),
        KEY_MAX,
        &config().into(),
        CompressedServerKey
    );
    let start = Instant::now();
    tfhe::set_server_key(key.decompress());
    let key_expand_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let unproven = compact.expand().map_err(|_| NATIVE)?;
    let compact_expand_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    // Includes a second proof verification: never describe this as pure expansion time.
    let verified = proof
        .verify_and_expand(&crs, &public, approved.as_bytes())
        .map_err(|_| NATIVE)?;
    let verified_expand_ns = start.elapsed().as_nanos();
    let mut sizes = [0usize; 2];
    for (kind, expander) in [unproven, verified].iter().enumerate() {
        need(expander.len() == 2, COUNT)?;
        for index in 0..2 {
            let value: FheUint8 = expander.get(index).map_err(|_| NATIVE)?.ok_or(NATIVE)?;
            let bytes = encode!(&value, CT_MAX);
            sizes[kind] += bytes.len();
            fs::write(root.join(format!("out-{kind}-{index}.bin")), bytes).map_err(|_| FRAMING)?;
        }
    }
    fs::write(
        root.join("metrics.txt"),
        format!(
            "{verify_ns},{compact_expand_ns},{verified_expand_ns},{key_expand_ns},{},{}",
            sizes[0], sizes[1]
        ),
    )
    .map_err(|_| TEST)?;
    Ok(())
}

pub(super) fn owner(root: &Path) -> Result<()> {
    let total = Instant::now();
    let start = Instant::now();
    let client = ClientKey::generate(config());
    let key = encode!(&CompressedServerKey::new(&client), KEY_MAX);
    let public = CompactPublicKey::try_new(&client).map_err(|_| PROFILE)?;
    let other = ClientKey::generate(config());
    let foreign = CompactPublicKey::try_new(&other).map_err(|_| PROFILE)?;
    let public_bytes = encode!(&public, CT_MAX);
    let foreign_bytes = encode!(&foreign, CT_MAX);
    let setup_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let crs = CompactPkeCrs::from_config(config(), 16).map_err(|_| PROFILE)?;
    let crs_bytes = encode!(&crs, 32 << 20);
    let crs_ns = start.elapsed().as_nanos();
    let setup = vec![key, crs_bytes, public_bytes, foreign_bytes];
    let approved = context(&setup);
    for ((name, _), bytes) in SETUP.iter().zip(&setup) {
        fs::write(root.join(name), bytes).map_err(|_| FRAMING)?;
    }
    let mut header = Vec::new();
    header.extend(2u32.to_le_bytes());
    header.extend(EXPANSION_MAX.to_le_bytes());
    header.extend(approved.as_bytes());
    fs::write(root.join("request.bin"), header).map_err(|_| FRAMING)?;
    let start = Instant::now();
    let native_bytes = [41u8, 255]
        .iter()
        .map(|value| {
            let ct = FheUint8::encrypt(*value, &client);
            Ok(encode!(&ct, CT_MAX).len())
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .sum::<usize>();
    let native_ns = start.elapsed().as_nanos();
    let mut builder = CompactCiphertextList::builder(&public);
    builder.push(41u8).push(255u8);
    let start = Instant::now();
    let compact = builder.build_packed();
    let compact_ns = start.elapsed().as_nanos();
    let compact_bytes = encode!(&compact, CT_MAX);
    let start = Instant::now();
    let proof = builder
        .build_with_proof_packed(&crs, approved.as_bytes(), ZkComputeLoad::Verify)
        .map_err(|_| NATIVE)?;
    let prove_ns = start.elapsed().as_nanos();
    let proof_bytes = encode!(&proof, PROOF_MAX);
    fs::write(root.join("compact.bin"), &compact_bytes).map_err(|_| FRAMING)?;
    fs::write(root.join("proof.bin"), &proof_bytes).map_err(|_| FRAMING)?;
    let mut child = Command::new(std::env::current_exe().map_err(|_| TEST)?)
        .args(["compact-verifier"])
        .arg(root)
        .arg(approved.to_hex().as_str())
        .env_clear()
        .env("RAYON_NUM_THREADS", "2")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| TEST)?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|_| TEST)? {
            need(status.success(), TEST)?;
            break;
        }
        if start.elapsed() > Duration::from_secs(480) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(TEST);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let start = Instant::now();
    for kind in 0..2 {
        for (index, expected) in [41u8, 255].iter().enumerate() {
            let value: u8 = decode_ct(&read(root, &format!("out-{kind}-{index}.bin"), CT_MAX)?)?
                .decrypt(&client);
            need(value == *expected, TEST)?;
        }
    }
    let decrypt_ns = start.elapsed().as_nanos();
    let metrics = read(root, "metrics.txt", 1024)?;
    let metrics = std::str::from_utf8(&metrics)
        .map_err(|_| TEST)?
        .split(',')
        .map(|value| value.parse::<u64>().map_err(|_| TEST))
        .collect::<Result<Vec<_>>>()?;
    need(metrics.len() == 6, TEST)?;
    println!(
        concat!(
            "{{\"experiment\":\"tfhe-compact\",\"values\":2,\"negative_cases\":6,\"integer_mismatches\":0,",
            "\"context_blake3\":\"{}\",\"crs_blake3\":\"{}\",\"public_key_blake3\":\"{}\",",
            "\"serialized_bytes\":{{\"native\":{},\"compact\":{},\"proven_list\":{},\"expanded_compact\":{},\"expanded_proven\":{},\"crs\":{},\"public_key\":{},\"evaluation_key\":{}}},",
            "\"stages_ns\":{{\"setup\":{},\"crs\":{},\"native_encrypt_encode\":{},\"compact_encrypt\":{},\"prove\":{},\"verify\":{},\"unproven_expand\":{},\"verified_expand\":{},\"key_expand\":{},\"owner_decrypt\":{},\"owner_total\":{}}}}}"
        ),
        approved,
        blake3::hash(&setup[1]),
        blake3::hash(&setup[2]),
        native_bytes,
        compact_bytes.len(),
        proof_bytes.len(),
        metrics[4],
        metrics[5],
        setup[1].len(),
        setup[2].len(),
        setup[0].len(),
        setup_ns,
        crs_ns,
        native_ns,
        compact_ns,
        prove_ns,
        metrics[0],
        metrics[1],
        metrics[2],
        metrics[3],
        decrypt_ns,
        total.elapsed().as_nanos()
    );
    Ok(())
}
