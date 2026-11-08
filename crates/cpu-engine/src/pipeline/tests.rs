use super::*;
use crate::fabric::{Fabric, Reply};
use hyper::http::HeaderMap;
use kryvola_cpu_engine::Engine;
use kryvola_engine_api::wire::{
    GetExecutionStatusRequest, engine_service_client::EngineServiceClient,
    engine_service_server::EngineServiceServer,
};
use ring::signature::{ED25519, KeyPair, UnparsedPublicKey};
use std::{
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, transport::Server};

type Artifact = (String, Vec<u8>, Bytes);

fn artifact(kind: &str, data: Bytes) -> Artifact {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../contracts/spec/fixtures/canonical-modular-v2.json"
    ))
    .unwrap();
    let mut manifest = fixture["objects"][0]["value"].clone();
    manifest["tenant_scope"] = json!("tenant-fixture");
    manifest["artifact_kind"] = json!(kind);
    manifest["native_codec_version"] = json!(NATIVE_CODEC);
    manifest["parameters"]["parameter_set_digest"] = json!(PARAMETERS);
    manifest["shape"] = json!(["2"]);
    manifest["serialized_bytes"] = json!(data.len().to_string());
    manifest["full_blob_digest"] = json!(digest(b"kryvola/blob/v1\0", &[&data]));
    manifest["max_expanded_bytes"] = json!(data.len().to_string());
    manifest["ordered_chunk_entries"] = json!(data.chunks(PART_MAX).enumerate().map(|(index, part)| {
        json!({"index":index.to_string(),"byte_offset":(index * PART_MAX).to_string(),
            "byte_length":part.len().to_string(),
            "chunk_digest":digest(b"kryvola/chunk/v1\0", &[&(index as u64).to_le_bytes(), &(part.len() as u64).to_le_bytes(), part])})
    }).collect::<Vec<_>>());
    let canonical = canonical(&manifest).unwrap();
    (
        digest(b"kryvola/manifest/v2\0", &[&canonical]),
        canonical,
        data,
    )
}

#[derive(Default)]
struct Stored {
    targets: Vec<String>,
    part: Bytes,
    manifest: Bytes,
    receipt: bool,
}
struct FabricFixture {
    inputs: [Artifact; 2],
    stored: Arc<Mutex<Stored>>,
    upload: String,
    corrupt: bool,
    public_key: Vec<u8>,
}

#[tonic::async_trait]
impl Fabric for FabricFixture {
    async fn call(
        &self,
        _: &str,
        path: &str,
        token: &str,
        body: Bytes,
        status: u16,
        limit: usize,
    ) -> Result<Reply> {
        let mut headers = HeaderMap::new();
        let mut saved = self.stored.lock().unwrap();
        let value = || serde_json::from_slice::<Value>(&body).unwrap();
        let upload = format!("/v1/uploads/{}", self.upload);
        let response = match path {
            p if p == "/v1/compute-inputs/manifest"
                || p.starts_with("/v1/compute-inputs/parts/") =>
            {
                assert_eq!(status, 200);
                let body = value();
                let index = self
                    .inputs
                    .iter()
                    .position(|a| a.0 == body["manifest_digest"])
                    .unwrap();
                let manifest = path.ends_with("manifest");
                let part = path.rsplit('/').next().unwrap();
                assert_eq!(token, format!("{index}-{part}"));
                let data = if manifest {
                    self.inputs[index].1.clone().into()
                } else if self.corrupt {
                    Bytes::from_static(b"corrupt!")
                } else {
                    let offset = part.parse::<usize>().unwrap() * PART_MAX;
                    let data = &self.inputs[index].2;
                    data.slice(offset..(offset + PART_MAX).min(data.len()))
                };
                headers.insert("content-type", "application/octet-stream".parse().unwrap());
                headers.insert("cache-control", "no-store".parse().unwrap());
                headers.insert("content-length", data.len().to_string().parse().unwrap());
                data
            }
            "/v1/executions/output-grants" => {
                assert_eq!(token, "issuer");
                saved
                    .targets
                    .push(value()["target"]["action"].as_str().unwrap().into());
                headers.insert("kryvola-output-grant", "a".repeat(64).parse().unwrap());
                headers.insert("cache-control", "no-store".parse().unwrap());
                json!({"schema_version":"1","expires_unix_ms":(now() + 10_000).to_string()})
                    .to_string()
                    .into()
            }
            "/v1/uploads" => {
                assert_eq!(status, 201);
                assert_eq!(token, "a".repeat(64));
                json!({"schema_version":"1","upload_id":self.upload})
                    .to_string()
                    .into()
            }
            p if p == format!("{upload}/parts/0") => {
                saved.part = body;
                Bytes::new()
            }
            p if p == format!("{upload}/manifest") => {
                saved.manifest = body;
                Bytes::new()
            }
            p if p == format!("{upload}/finalize") => {
                let commitment = digest(b"kryvola/manifest/v2\0", &[&saved.manifest]);
                assert_eq!(value()["manifest_digest"], commitment);
                json!({"schema_version":"1","manifest_digest":commitment})
                    .to_string()
                    .into()
            }
            "/v1/executions/receipt" => {
                assert_eq!(token, "receipt");
                let body = value();
                assert_eq!(body["output_upload_id"], self.upload);
                let receipt = URL_SAFE_NO_PAD
                    .decode(body["receipt_base64url"].as_str().unwrap())
                    .unwrap();
                let mut envelope: Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(body["signature_base64url"].as_str().unwrap())
                        .unwrap(),
                )
                .unwrap();
                let signature = envelope
                    .as_object_mut()
                    .unwrap()
                    .remove("signature")
                    .unwrap();
                let commitment = digest(b"kryvola/receipt/v3\0", &[&receipt]);
                assert_eq!(envelope["payload_digest"], commitment);
                let mut preimage = b"kryvola/signature/receipt/v3\0".to_vec();
                for data in [&canonical(&envelope).unwrap(), &receipt] {
                    preimage.extend_from_slice(&(data.len() as u64).to_le_bytes());
                    preimage.extend_from_slice(data);
                }
                UnparsedPublicKey::new(&ED25519, &self.public_key)
                    .verify(
                        &preimage,
                        &URL_SAFE_NO_PAD.decode(signature.as_str().unwrap()).unwrap(),
                    )
                    .unwrap();
                saved.receipt = true;
                json!({"schema_version":"1","receipt_digest":commitment})
                    .to_string()
                    .into()
            }
            _ => panic!("unexpected Fabric route"),
        };
        assert!(response.len() <= limit);
        Ok(Reply {
            headers,
            body: response,
        })
    }
}

async fn rpc(
    execution: &str,
    upload: String,
    corrupt: bool,
    native: Option<&Path>,
) -> Option<ArtifactRef> {
    let key = Ed25519KeyPair::from_seed_unchecked(&[17; 32]).unwrap();
    let payload = |name: &str, fallback: &'static [u8]| -> Bytes {
        native.map_or_else(
            || Bytes::from_static(fallback),
            |dir| std::fs::read(dir.join(name)).unwrap().into(),
        )
    };
    let inputs = [
        artifact("EVALUATION_KEY", payload("key", b"eval-key")),
        artifact("CIPHERTEXT", payload("input", b"ct-input")),
    ];
    let reads = std::array::from_fn(|index| {
        let parts = inputs[index].2.len().div_ceil(PART_MAX);
        std::iter::once(format!("{index}-manifest"))
            .chain((0..parts).map(|p| format!("{index}-{p}")))
            .collect()
    });
    let mut approved: ExecuteRequest = codec::fixture("ExecuteRequest");
    approved.program_digest = Some(PROGRAM.into());
    approved.parameter_set_digest = Some(PARAMETERS.into());
    approved.required_operators.push("MUL".into());
    let deadline = (now() + 45_000).to_string();
    let ex = approved.execution.as_mut().unwrap();
    ex.execution_id = Some(execution.into());
    ex.deadline_unix_ms = Some(deadline.clone());
    approved.operation.as_mut().unwrap().deadline_unix_ms = Some(deadline);
    let query = GetExecutionStatusRequest {
        schema_version: Some("1".into()),
        attempt: ex.attempt.clone(),
        execution_id: ex.execution_id.clone(),
    };
    let original = approved.input_refs[0].clone();
    approved.input_refs = inputs
        .iter()
        .map(|(id, _, bytes)| ArtifactRef {
            manifest_digest: id.clone(),
            byte_length: bytes.len().to_string(),
            ..original.clone()
        })
        .collect();
    let scratch = tempfile::tempdir().unwrap();
    let evaluator = if let Some(native) = native {
        std::fs::read_link(native.join("evaluator")).unwrap()
    } else {
        let evaluator = scratch.path().join("stub");
        std::fs::write(&evaluator, "#!/bin/sh\nprintf cipher-output > \"$4\"\n").unwrap();
        std::fs::set_permissions(&evaluator, std::fs::Permissions::from_mode(0o700)).unwrap();
        evaluator
    };
    let stored = Arc::new(Mutex::new(Stored::default()));
    let worker = Pipeline {
        fabric: FabricFixture {
            inputs,
            stored: stored.clone(),
            upload,
            corrupt,
            public_key: key.public_key().as_ref().into(),
        },
        credentials: Credentials {
            reads,
            output: "issuer".into(),
            receipt: "receipt".into(),
        },
        receipt: ReceiptPolicy {
            signer: "engine-test".into(),
            key_id: "test-key".into(),
            key_epoch: "1".into(),
            policy_epoch: "1".into(),
            consent_digest: "1".repeat(64),
            model_digest: "2".repeat(64),
            capability_profile_digest: "3".repeat(64),
            leakage_profile_digest: "4".repeat(64),
            evidence_policy_digest: "5".repeat(64),
        },
        key,
        evaluator,
        supervisor: Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/cpu_runner.py"),
    };
    let service = EngineServiceServer::new(Engine::new(approved.clone(), worker).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        Server::builder()
            .add_service(service)
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    let mut client = EngineServiceClient::connect(format!("http://{address}"))
        .await
        .unwrap();
    let mut substituted = approved.clone();
    substituted.input_refs[0].manifest_digest = "a".repeat(64);
    assert_eq!(
        client.execute(substituted).await.unwrap_err().code(),
        Code::PermissionDenied
    );
    client.execute(approved.clone()).await.unwrap();
    client.execute(approved).await.unwrap();
    let observation = tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            let result = client
                .get_execution_status(query.clone())
                .await
                .unwrap()
                .into_inner();
            if result.execution.as_ref().unwrap().physical_state.as_deref() != Some("RUNNING") {
                break result;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    server.abort();
    let stored = stored.lock().unwrap();
    if corrupt {
        assert_eq!(observation.error_code.as_deref(), Some("INVALID_REQUEST"));
        assert!(stored.targets.is_empty());
    } else {
        assert_eq!(observation.error_code.as_deref(), Some("NONE"));
        assert_eq!(
            stored.targets,
            ["RESERVE", "PUT_PART", "PUT_MANIFEST", "FINALIZE"]
        );
        if let Some(native) = native {
            std::fs::write(native.join("output"), &stored.part).unwrap();
        } else {
            assert_eq!(stored.part, "cipher-output");
        }
        assert!(stored.receipt);
    }
    observation.output_refs.into_iter().next()
}

#[tokio::test]
async fn artifact_rpc_publishes_only_verified_inputs_and_distinct_outputs() {
    let first = rpc("execution-a", "a".repeat(32), false, None)
        .await
        .unwrap();
    let second = rpc("execution-b", "b".repeat(32), false, None)
        .await
        .unwrap();
    assert_eq!(first.manifest_digest, second.manifest_digest);
    assert_ne!(first.opaque_artifact_id, second.opaque_artifact_id);
    assert!(
        rpc("execution-c", "c".repeat(32), true, None)
            .await
            .is_none()
    );
}

#[tokio::test]
#[ignore = "requires the separately built owner fixture and CPU evaluator"]
async fn native_artifact_rpc() {
    let directory = PathBuf::from(std::env::var_os("KRYVOLA_ENGINE_FIXTURE").unwrap());
    assert!(
        rpc("native-execution", "d".repeat(32), false, Some(&directory))
            .await
            .is_some()
    );
}
