//! Local file adapter; the authorized launcher supplies paths and expected digests.
#![forbid(unsafe_code)]

use kryvola_cpu_evaluator::{EvaluationBinding, KEY_MAX, PAIR_MAX, evaluate};
use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

type Result<T> = std::result::Result<T, &'static str>;

fn digest(value: &OsStr) -> Result<[u8; 32]> {
    let value = value.to_str().ok_or("EVALUATOR_ARGUMENT")?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("EVALUATOR_ARGUMENT");
    }
    Ok(*blake3::Hash::from_hex(value)
        .map_err(|_| "EVALUATOR_ARGUMENT")?
        .as_bytes())
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|_| "EVALUATOR_IO")?;
    let metadata = file.metadata().map_err(|_| "EVALUATOR_IO")?;
    if !metadata.is_file() {
        return Err("EVALUATOR_IO");
    }
    if metadata.len() > maximum as u64 {
        return Err("EVALUATOR_SIZE");
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "EVALUATOR_IO")?;
    if bytes.len() > maximum {
        return Err("EVALUATOR_SIZE");
    }
    Ok(bytes)
}

fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() == 2 && args[1] == "--help" {
        println!("research-only: evaluate KEY INPUT OUTPUT KEY_DIGEST INPUT_DIGEST");
        return Ok(());
    }
    if args.len() != 7 || args[1] != "evaluate" {
        return Err("EVALUATOR_ARGUMENT");
    }
    let binding = EvaluationBinding {
        evaluation_key_digest: digest(&args[5])?,
        input_blob_digest: digest(&args[6])?,
    };
    let key = read(Path::new(&args[2]), KEY_MAX)?;
    let input = read(Path::new(&args[3]), PAIR_MAX)?;
    let result = evaluate(binding, &key, &input).map_err(|error| error.code())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(Path::new(&args[4]))
        .map_err(|_| "EVALUATOR_IO")?;
    output.write_all(&result).map_err(|_| "EVALUATOR_IO")
}

fn main() {
    if let Err(code) = run() {
        eprintln!("{code}");
        std::process::exit(2);
    }
}
