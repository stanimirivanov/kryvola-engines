//! Fixed research circuit. ClientKey exists only in owner(); evaluator sees ciphertexts.
use super::*;

const CASES: usize = 100;
const BATCH_MAX: u64 = 32 << 20;
const PROGRAM: &[u8] = include_bytes!("../fixtures/fhe-q1/program.txt");
const INPUTS: &str = include_str!("../fixtures/fhe-q1/inputs.csv");
const EXPECTED: &str = include_str!("../fixtures/fhe-q1/expected.csv");

pub(super) fn workload() -> blake3::Hash {
    let mut hash = blake3::Hasher::new_derive_key("kryvola/research/fhe-q1/binding/v1");
    let parameters = profile();
    for bytes in [
        PROGRAM,
        INPUTS.as_bytes(),
        EXPECTED.as_bytes(),
        parameters.as_bytes(),
    ] {
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hash.finalize()
}

fn pairs(raw: &str) -> Result<Vec<(u8, u8)>> {
    let result = raw
        .lines()
        .skip(1)
        .map(|line| {
            let (a, b) = line.split_once(',').ok_or(TEST)?;
            Ok((a.parse().map_err(|_| TEST)?, b.parse().map_err(|_| TEST)?))
        })
        .collect::<Result<Vec<_>>>()?;
    need(result.len() == CASES, COUNT)?;
    Ok(result)
}

fn pack(values: &[FheUint8]) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    for value in values {
        let bytes = encode!(value, CT_MAX);
        need(
            result.len() as u64 + 8 + bytes.len() as u64 <= BATCH_MAX,
            SIZE,
        )?;
        result.extend((bytes.len() as u64).to_le_bytes());
        result.extend(bytes);
    }
    need(result.len() as u64 <= BATCH_MAX, SIZE)?;
    Ok(result)
}

fn unpack(bytes: &[u8]) -> Result<Vec<FheUint8>> {
    let mut cursor = Cursor::new(bytes);
    let mut values = Vec::with_capacity(CASES * 2);
    for _ in 0..CASES * 2 {
        let length = u64::from_le_bytes(take(&mut cursor)?);
        need(
            length > 0 && length <= CT_MAX && length <= bytes.len() as u64 - cursor.position(),
            SIZE,
        )?;
        let mut encoded = vec![0; length as usize];
        cursor.read_exact(&mut encoded).map_err(|_| FRAMING)?;
        values.push(decode_ct(&encoded)?);
    }
    need(cursor.position() == bytes.len() as u64, FRAMING)?;
    Ok(values)
}

fn rss() -> Result<u64> {
    let status = fs::read_to_string("/proc/self/status").map_err(|_| TEST)?;
    status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(|value| value.checked_mul(1024))
        .ok_or(TEST)
}

pub(super) fn evaluator(root: &Path, context: blake3::Hash, approved: blake3::Hash) -> Result<()> {
    let start = Instant::now();
    let (key, bytes) = read_input(root, context, approved, (CASES * 2) as u32, BATCH_MAX)?;
    let inputs = unpack(&bytes)?;
    let decode_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    tfhe::set_server_key(key.decompress());
    let expand_ns = start.elapsed().as_nanos();
    let mut output = Vec::with_capacity(CASES * 2);
    let mut rows = Vec::with_capacity(CASES);
    for (index, pair) in inputs.chunks_exact(2).enumerate() {
        let start = Instant::now();
        let a = &pair[0] * 3u8;
        let b = &pair[1] * 5u8;
        let y0 = (&a + &b) + 7u8;
        let y1 = (&pair[0] * &pair[1]) + 11u8;
        let elapsed = start.elapsed().as_nanos();
        output.extend([y0, y1]);
        rows.push(format!("[{index},{elapsed}]"));
    }
    let start = Instant::now();
    let encoded = pack(&output)?;
    let encode_ns = start.elapsed().as_nanos();
    fs::write(root.join("output.bin"), encoded).map_err(|_| FRAMING)?;
    // Only bounded numeric metadata goes to the owner's report reader.
    fs::write(
        root.join("metrics.txt"),
        format!(
            "{decode_ns},{expand_ns},{encode_ns},{}\n{}",
            rss()?,
            rows.join(",")
        ),
    )
    .map_err(|_| TEST)?;
    Ok(())
}

pub(super) fn owner(root: &Path) -> Result<()> {
    let total = Instant::now();
    let start = Instant::now();
    let client = ClientKey::generate(ConfigBuilder::with_custom_parameters(PARAMETERS).build());
    let key = encode!(&CompressedServerKey::new(&client), KEY_MAX);
    let keygen_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let mut inputs = Vec::with_capacity(CASES * 2);
    for (a, b) in pairs(INPUTS)? {
        inputs.extend([FheUint8::encrypt(a, &client), FheUint8::encrypt(b, &client)]);
    }
    let ct = pack(&inputs)?;
    let encrypt_ns = start.elapsed().as_nanos();
    let context = blake3::hash(&key);
    let mut envelope = packet(&key, &ct, context);
    envelope[80..84].copy_from_slice(&((CASES * 2) as u32).to_le_bytes());
    let mut invalid = envelope[..HEADER].to_vec();
    invalid[80..84].copy_from_slice(&199u32.to_le_bytes());
    dispatch_mode(
        root,
        &invalid,
        context,
        blake3::hash(&ct),
        COUNT,
        "frozen-evaluator",
    )?;
    let start = Instant::now();
    dispatch_mode(
        root,
        &envelope,
        context,
        blake3::hash(&ct),
        0,
        "frozen-evaluator",
    )?;
    let dispatch_ns = start.elapsed().as_nanos();
    let start = Instant::now();
    let mut bytes = Vec::new();
    File::open(root.join("output.bin"))
        .map_err(|_| TEST)?
        .take(BATCH_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| TEST)?;
    need(bytes.len() as u64 <= BATCH_MAX, SIZE)?;
    let output = unpack(&bytes)?;
    for (pair, (a, b)) in output.chunks_exact(2).zip(pairs(EXPECTED)?) {
        let actual: (u8, u8) = (pair[0].decrypt(&client), pair[1].decrypt(&client));
        need(actual == (a, b), TEST)?;
    }
    let decrypt_ns = start.elapsed().as_nanos();
    let mut metrics = String::new();
    File::open(root.join("metrics.txt"))
        .map_err(|_| TEST)?
        .take(8193)
        .read_to_string(&mut metrics)
        .map_err(|_| TEST)?;
    need(metrics.len() <= 8192, SIZE)?;
    let (header, rows) = metrics.split_once('\n').ok_or(TEST)?;
    let shared = header
        .split(',')
        .map(|v| v.parse::<u64>().map_err(|_| TEST))
        .collect::<Result<Vec<_>>>()?;
    need(
        shared.len() == 4 && rows.matches('[').count() == CASES,
        TEST,
    )?;
    need(
        rows.bytes()
            .all(|b| b.is_ascii_digit() || b"[],".contains(&b)),
        TEST,
    )?;
    println!(
        concat!(
            "{{\"experiment\":\"tfhe-eval\",\"cases\":100,\"integer_mismatches\":0,\"negative_cases\":1,",
            "\"binding_blake3\":\"{}\",\"parameter_blake3\":\"{}\",\"key_context_blake3\":\"{}\",",
            "\"program_blake3\":\"{}\",\"fixture_blake3\":\"{}\",\"input_blake3\":\"{}\",",
            "\"stages_ns\":{{\"keygen\":{},\"encrypt_encode\":{},\"dispatch\":{},\"owner_decode_decrypt\":{},",
            "\"native_decode\":{},\"key_expand\":{},\"native_encode\":{},\"owner_total\":{}}},",
            "\"serialized_key_bytes\":{},\"serialized_input_bytes\":{},\"serialized_output_bytes\":{},",
            "\"owner_peak_rss_bytes\":{},\"evaluator_peak_rss_bytes\":{},\"reservation_bytes\":{},",
            "\"observations\":[{}]}}"
        ),
        workload(),
        profile(),
        context,
        blake3::hash(PROGRAM),
        blake3::hash(include_bytes!("../fixtures/fhe-q1/manifest.json")),
        blake3::hash(&ct),
        keygen_ns,
        encrypt_ns,
        dispatch_ns,
        decrypt_ns,
        shared[0],
        shared[1],
        shared[2],
        total.elapsed().as_nanos(),
        key.len(),
        ct.len(),
        bytes.len(),
        rss()?,
        shared[3],
        reservation(),
        rows
    );
    Ok(())
}
