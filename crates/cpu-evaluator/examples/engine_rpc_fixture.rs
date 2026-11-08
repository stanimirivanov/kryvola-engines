//! Owner-side qualification fixture. Only public evaluation material leaves this process.
use std::{
    fs,
    os::unix::fs::{DirBuilderExt, symlink},
    path::{Path, PathBuf},
    process::Command,
};

use kryvola_owner_crypto::{OpenBinding, OwnerKey, blob_digest};

fn main() {
    let mut args = std::env::args_os().skip(1);
    let scratch = PathBuf::from(args.next().expect("private fixture path"));
    let evaluator = PathBuf::from(args.next().expect("evaluator binary"))
        .canonicalize()
        .unwrap();
    assert!(args.next().is_none());
    fs::DirBuilder::new().mode(0o700).create(&scratch).unwrap();
    let owner = OwnerKey::generate().unwrap();
    fs::write(scratch.join("key"), owner.evaluation_key()).unwrap();
    fs::write(scratch.join("input"), owner.encrypt_pair([3, 4]).unwrap()).unwrap();
    symlink(evaluator, scratch.join("evaluator")).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let status = Command::new("cargo")
        .current_dir(root)
        .args([
            "test",
            "--locked",
            "-p",
            "kryvola-cpu-engine",
            "native_artifact_rpc",
            "--",
            "--ignored",
        ])
        .env("KRYVOLA_ENGINE_FIXTURE", &scratch)
        .status()
        .unwrap();
    assert!(status.success());
    let result = fs::read(scratch.join("output")).unwrap();
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
        [36, 23]
    );
}
