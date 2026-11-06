use kryvola_owner_crypto::{OpenBinding, OwnerKey, blob_digest};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_kryvola-cpu-evaluator")
}

#[test]
fn unsupported_owner_routes_fail_before_reading_files() {
    for route in ["owner", "decrypt", "keygen", "import-key", "--unknown"] {
        let output = Command::new(binary()).arg(route).output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"EVALUATOR_ARGUMENT\n");
    }
}

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn worker_process_round_trips_frozen_edges_with_public_files_only() {
    let owner = OwnerKey::generate().unwrap();
    let root = std::env::temp_dir().join(format!(
        "cpu-evaluator-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let _fixture = Fixture(root.clone());
    fs::write(root.join("evaluation.bin"), owner.evaluation_key()).unwrap();
    let key_digest = blake3::Hash::from(blob_digest(owner.evaluation_key()))
        .to_hex()
        .to_string();
    let pairs = |csv: &str| -> Vec<[u8; 2]> {
        csv.lines()
            .skip(1)
            .map(|line| {
                let (a, b) = line.split_once(',').unwrap();
                [a.parse().unwrap(), b.parse().unwrap()]
            })
            .collect()
    };
    let inputs = pairs(include_str!(
        "../../../experiments/tfhe/fixtures/fhe-q1/inputs.csv"
    ));
    let expected = pairs(include_str!(
        "../../../experiments/tfhe/fixtures/fhe-q1/expected.csv"
    ));
    // Sparse oversized files fail at the file boundary, before any native decode.
    fs::File::create(root.join("oversized.bin"))
        .unwrap()
        .set_len((64 << 20) + 1)
        .unwrap();
    let output = Command::new(binary())
        .current_dir(&root)
        .args([
            "evaluate",
            "oversized.bin",
            "missing-input",
            "unused-output",
            &key_digest,
            &"0".repeat(64),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(output.stderr, b"EVALUATOR_SIZE\n");
    fs::OpenOptions::new()
        .write(true)
        .open(root.join("oversized.bin"))
        .unwrap()
        .set_len((2 * ((1 << 20) + 8) + 1) as u64)
        .unwrap();
    let output = Command::new(binary())
        .current_dir(&root)
        .args([
            "evaluate",
            "evaluation.bin",
            "oversized.bin",
            "unused-output",
            &key_digest,
            &"0".repeat(64),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(output.stderr, b"EVALUATOR_SIZE\n");
    fs::remove_file(root.join("oversized.bin")).unwrap();
    for index in [0, 9, 90, 99] {
        let input = owner.encrypt_pair(inputs[index]).unwrap();
        fs::write(root.join("input.bin"), &input).unwrap();
        let input_digest = blake3::Hash::from(blob_digest(&input)).to_hex().to_string();
        let run = || {
            Command::new(binary())
                .current_dir(&root)
                .args([
                    "evaluate",
                    "evaluation.bin",
                    "input.bin",
                    "output.bin",
                    &key_digest,
                    &input_digest,
                ])
                .output()
                .unwrap()
        };
        let output = run();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
        let result = fs::read(root.join("output.bin")).unwrap();
        assert_eq!(
            owner
                .open_result(
                    OpenBinding {
                        evaluation_key_digest: blob_digest(owner.evaluation_key()),
                        result_blob_digest: blob_digest(&result),
                    },
                    &result
                )
                .unwrap(),
            expected[index]
        );
        if index == 0 {
            assert_eq!(run().stderr, b"EVALUATOR_IO\n"); // Never overwrite an existing result.
            assert_eq!(fs::read(root.join("output.bin")).unwrap(), result);
        }
        fs::remove_file(root.join("output.bin")).unwrap();
    }
    let files: std::collections::BTreeSet<_> = fs::read_dir(&root)
        .unwrap()
        .map(|p| p.unwrap().file_name())
        .collect();
    assert_eq!(
        files,
        ["evaluation.bin", "input.bin"]
            .into_iter()
            .map(Into::into)
            .collect()
    );
}

#[test]
fn malformed_commitments_fail_before_file_access_without_echoing_arguments() {
    for bad in [
        "".to_owned(),
        "0".repeat(63),
        "A".repeat(64),
        "g".repeat(64),
    ] {
        let output = Command::new(binary())
            .args([
                "evaluate",
                "private-path-marker",
                "missing-input",
                "unused-output",
                &bad,
                &"0".repeat(64),
            ])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"EVALUATOR_ARGUMENT\n");
    }
}
