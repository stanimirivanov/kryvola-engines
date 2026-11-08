//! Worker entry point. The launch directory is owned by the trusted dispatcher.
mod fabric;
mod pipeline;

use std::{
    error::Error,
    fs::File,
    io::Read,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use kryvola_cpu_engine::Engine;
use kryvola_engine_api::{
    codec,
    wire::{ExecuteRequest, engine_service_server::EngineServiceServer},
};
use prost::Message;
use ring::signature::Ed25519KeyPair;
use serde::Deserialize;
use spiffe::{SpiffeId, X509Source, X509Svid, x509_source::SvidPicker};
use spiffe_rustls::{LocalOnly, TerminalSourcePolicy, authorizer, mtls_client};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

use crate::pipeline::{Credentials, Pipeline, ReceiptPolicy};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Assignment {
    execute_protobuf_hex: String,
    fabric_address: SocketAddr,
    fabric_id: String,
    workload_endpoint: String,
    worker_id: String,
    credentials: Credentials,
    receipt: ReceiptPolicy,
    receipt_key: PathBuf,
    evaluator: PathBuf,
    supervisor: PathBuf,
}

#[derive(Debug)]
struct Picker(SpiffeId);
impl SvidPicker for Picker {
    fn pick_svid(&self, svids: &[Arc<X509Svid>]) -> Option<usize> {
        svids.iter().position(|svid| svid.spiffe_id() == &self.0)
    }
}

fn read_private(path: &Path, limit: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("private file required".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("file exceeds budget".into());
    }
    Ok(bytes)
}

async fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let root = PathBuf::from(args.next().ok_or("launch directory required")?);
    let metadata = root.metadata()?;
    if args.next().is_some()
        || !root.is_absolute()
        || !metadata.is_dir()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("private launch directory required".into());
    }
    let config: Assignment =
        serde_json::from_slice(&read_private(&root.join("assignment.json"), 384 << 10)?)?;
    let bytes = hex::decode(config.execute_protobuf_hex)?;
    codec::validate::<ExecuteRequest>(&bytes)?;
    let request = ExecuteRequest::decode(bytes.as_slice())?;
    if !config.workload_endpoint.starts_with("unix://")
        || !config.evaluator.is_absolute()
        || !config.supervisor.is_absolute()
        || !config.receipt_key.is_absolute()
    {
        return Err("invalid worker paths".into());
    }
    let key = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&read_private(&config.receipt_key, 1024)?)
        .map_err(|_| "invalid signing key")?;
    let worker_id: SpiffeId = config.worker_id.parse()?;
    let domain = worker_id.trust_domain().clone();
    let source = tokio::time::timeout(
        Duration::from_secs(10),
        X509Source::builder()
            .endpoint(config.workload_endpoint)
            .picker(Picker(worker_id))
            .build(),
    )
    .await??;
    source.svid()?;
    let tls = mtls_client(source)
        .authorize(authorizer::exact([config.fabric_id])?)
        .trust_domain_policy(LocalOnly(domain))
        .terminal_source_policy(TerminalSourcePolicy::FailClosed)
        .build()?;
    let worker = Pipeline {
        fabric: fabric::Client {
            address: config.fabric_address,
            tls: Arc::new(tls),
        },
        credentials: config.credentials,
        receipt: config.receipt,
        key,
        evaluator: config.evaluator,
        supervisor: config.supervisor,
    };
    let service = EngineServiceServer::new(Engine::new(request, worker)?)
        .max_decoding_message_size(fabric::CONTROL)
        .max_encoding_message_size(fabric::CONTROL);
    let socket = root.join("engine.sock");
    let listener = tokio::net::UnixListener::bind(&socket)?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;
    Server::builder()
        .add_service(service)
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("ENGINE_STARTUP_FAILED");
        std::process::exit(2);
    }
}
