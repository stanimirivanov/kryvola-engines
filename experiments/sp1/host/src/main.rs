#![forbid(unsafe_code)]
#![deny(warnings)]

use kryvola_sp1_statement::{journal, CYCLES};
use sp1_sdk::{prelude::*, ProverClient, SP1Proof, SP1PublicValues};
use std::{
    fs,
    sync::atomic::{AtomicU8, Ordering},
    time::Instant,
};

static STAGE: AtomicU8 = AtomicU8::new(0);
fn stage(value: u8) {
    STAGE.store(value, Ordering::Relaxed);
    eprintln!("KRY_SP1_STAGE={value}");
}

const ELF_BYTES: &[u8] = include_bytes!(env!("KRYVOLA_SP1_ELF"));
const OTHER_BYTES: &[u8] = include_bytes!(env!("KRYVOLA_SP1_OTHER_ELF"));

fn allowed(mode: &str, dev: bool) -> bool {
    mode == "cpu" && !dev
}
fn program_matches(bytes: &[u8], expected: blake3::Hash) -> bool {
    blake3::hash(bytes) == expected
}

fn input(fields: [[u8; 32]; 3], mode: u8) -> SP1Stdin {
    let mut input = SP1Stdin::new();
    for field in fields {
        input.write(&field);
    }
    input.write(&mode);
    input
}

async fn experiment() -> Result<(), Box<dyn std::error::Error>> {
    stage(1); // mode and statement preparation
    assert!(allowed(
        &std::env::var("SP1_PROVER").unwrap_or_else(|_| "cpu".into()),
        std::env::var_os("SP1_DEV_MODE").is_some()
    ));
    let total = Instant::now();
    let elf = Elf::Static(ELF_BYTES);
    let digest = blake3::hash(ELF_BYTES);
    assert!(program_matches(ELF_BYTES, digest));
    let fields = [[0x11; 32], *digest.as_bytes(), [0x22; 32]];
    let expected = journal(fields, 1).ok_or("STATEMENT")?;
    let mut options = sp1_core_executor::SP1CoreOpts::default();
    options.shard_size = 1 << 16;
    // The default shared-memory trace ring exceeds our 128 MiB file limit.
    // Bound executor buffering independently of proof trace sharding.
    options.minimal_trace_chunk_threshold = 1 << 16;
    options.trace_chunk_slots = 2;
    stage(2); // CPU client initialization
    let client = ProverClient::builder()
        .cpu()
        .core_opts(options)
        .build()
        .await;
    stage(3); // program setup
    let pk = client.setup(elf.clone()).await?;
    let other = client.setup(Elf::Static(OTHER_BYTES)).await?;
    stage(4); // successful execution proof
    let start = Instant::now();
    let proof = client
        .prove(&pk, input(fields, 1))
        .core()
        .cycle_limit(CYCLES)
        .await?;
    let prove_ns = start.elapsed().as_nanos();
    stage(5); // proof mode and journal binding
    assert!(matches!(&proof.proof, SP1Proof::Core(shards) if !shards.is_empty()));
    assert_eq!(proof.public_values.as_slice(), expected.as_slice());
    let start = Instant::now();
    stage(6); // successful proof verification
    client.verify(&proof, pk.verifying_key(), None)?; // None requires SUCCESS, not arbitrary exit.
    let verify_ns = start.elapsed().as_nanos();
    stage(7); // changed journal rejection
    let mut changed = proof.clone();
    let mut wrong = expected.clone();
    wrong[0] ^= 1;
    changed.public_values = SP1PublicValues::from(wrong.as_slice());
    assert!(client.verify(&changed, pk.verifying_key(), None).is_err());
    drop(changed);
    stage(8); // changed program/key rejection
    assert!(!program_matches(OTHER_BYTES, digest)); // independent program identity gate
    assert!(client.verify(&proof, other.verifying_key(), None).is_err());
    stage(9); // proof of failed execution
    let invalid = client
        .prove(&pk, input(fields, 2))
        .core()
        .cycle_limit(CYCLES)
        .expected_exit_code(sp1_sdk::StatusCode::new(1).ok_or("FAILURE_STATUS")?)
        .await?;
    stage(10); // failed execution rejection
    client.verify(&invalid, pk.verifying_key(), sp1_sdk::StatusCode::new(1))?;
    assert!(client.verify(&invalid, pk.verifying_key(), None).is_err());
    drop(invalid);
    stage(11); // mock/dev rejection
    let mut mock = proof.clone();
    mock.proof = SP1Proof::Core(Vec::new());
    assert!(client.verify(&mock, pk.verifying_key(), None).is_err());
    assert!(!allowed("mock", false));
    assert!(!allowed("cpu", true));
    stage(12); // proof serialization and report
    let path = std::env::args_os().nth(1).ok_or("OUTPUT_PATH")?;
    proof.save(&path)?;
    let size = fs::metadata(&path)?.len();
    assert!(size > 0 && size <= 128 << 20);
    let vk = pk.verifying_key().bytes32();
    println!(concat!("{{\"experiment\":\"sp1-relation\",\"mode\":\"CORE_CPU\",\"outcome\":0,",
        "\"negative_cases\":7,\"elf_blake3\":\"{}\",\"vk_digest\":\"{}\",\"journal_blake3\":\"{}\",",
        "\"journal_bytes\":{},\"proof_bytes\":{},\"cycle_limit\":{},\"prove_ns\":{},\"verify_ns\":{},\"total_ns\":{}}}"),
        digest, vk.trim_start_matches("0x"), blake3::hash(&expected), expected.len(), size,
        CYCLES, prove_ns, verify_ns, total.elapsed().as_nanos());
    Ok(())
}

#[tokio::main(worker_threads = 2)]
async fn main() {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("KRY_SP1_PANIC={}", STAGE.load(Ordering::Relaxed))
    }));
    if let Err(error) = experiment().await {
        let kind = match error.downcast_ref::<sp1_sdk::cpu::CPUProverError>() {
            Some(sp1_sdk::cpu::CPUProverError::Execution(_)) => "EXECUTION",
            Some(sp1_sdk::cpu::CPUProverError::Prover(_)) => "PROVER",
            Some(sp1_sdk::cpu::CPUProverError::Unexpected(_)) => "UNEXPECTED",
            None if error.is::<sp1_sdk::SP1VerificationError>() => "VERIFY",
            None => "OTHER",
        };
        eprintln!("KRY_SP1_ERROR={kind}");
        std::process::exit(1);
    }
}
