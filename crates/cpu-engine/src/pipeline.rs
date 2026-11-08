use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use kryvola_engine_api::{
    codec,
    wire::{ArtifactRef, ExecuteRequest},
};
use ring::signature::Ed25519KeyPair;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::fabric::{CONTROL, Fabric, Reply, Result};
use kryvola_cpu_engine::{Evaluation, PARAMETERS, PROGRAM, now};

const KEY_MAX: usize = 64 << 20;
const PAIR_MAX: usize = 2 * (8 + (1 << 20));
const PART_MAX: usize = 4 << 20;
const NATIVE_CODEC: &str = "tfhe-rs-1.8.1";
const MEDIA: &str = "application/vnd.kryvola.tfhe-ciphertext";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Credentials {
    /// One fresh token for the manifest followed by one per indexed part.
    pub reads: [Vec<String>; 2],
    pub output: String,
    pub receipt: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiptPolicy {
    pub signer: String,
    pub key_id: String,
    pub key_epoch: String,
    pub policy_epoch: String,
    pub consent_digest: String,
    pub model_digest: String,
    pub capability_profile_digest: String,
    pub leakage_profile_digest: String,
    pub evidence_policy_digest: String,
}

pub(crate) struct Pipeline<F> {
    pub fabric: F,
    pub credentials: Credentials,
    pub receipt: ReceiptPolicy,
    pub key: Ed25519KeyPair,
    pub evaluator: PathBuf,
    pub supervisor: PathBuf,
}

fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut value = value.clone();
    value.sort_all_objects();
    let bytes = serde_json::to_vec(&value).map_err(|_| "INTERNAL")?;
    if !bytes.is_ascii() || bytes.len() > CONTROL {
        return Err("INVALID_REQUEST");
    }
    Ok(bytes)
}

fn digest(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    for part in parts {
        hash.update(part);
    }
    hash.finalize().to_hex().to_string()
}

fn number(value: &Value) -> Result<usize> {
    value
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or("INVALID_REQUEST")
}

fn binary(reply: Reply, length: Option<usize>) -> Result<Bytes> {
    if reply
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        != Some("application/octet-stream")
        || reply
            .headers
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            != Some("no-store")
        || reply.headers.contains_key("content-encoding")
        || reply
            .headers
            .get("content-length")
            .and_then(|v| v.to_str().ok()?.parse::<usize>().ok())
            != Some(reply.body.len())
        || length.is_some_and(|n| n != reply.body.len())
    {
        return Err("INVALID_REQUEST");
    }
    Ok(reply.body)
}

fn validate(
    value: &Value,
    schema: &'static str,
    slot: &'static OnceLock<Option<jsonschema::Validator>>,
) -> Result<()> {
    let validator = slot
        .get_or_init(|| {
            jsonschema::validator_for(&serde_json::from_str::<Value>(schema).ok()?).ok()
        })
        .as_ref()
        .ok_or("INTERNAL")?;
    if validator.is_valid(value) {
        Ok(())
    } else {
        Err("INVALID_REQUEST")
    }
}

fn manifest_schema(value: &Value) -> Result<()> {
    static SCHEMA: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
    validate(
        value,
        include_str!("../../../contracts/spec/canonical/v2/manifest.schema.json"),
        &SCHEMA,
    )
}

struct Input {
    manifest: Value,
    digest: String,
}

impl<F: Fabric> Pipeline<F> {
    async fn fetch(&self, ctx: &Run<'_>, index: usize, path: &Path) -> Result<Input> {
        let (kind, max) = [("EVALUATION_KEY", KEY_MAX), ("CIPHERTEXT", PAIR_MAX)][index];
        let reference = &ctx.request.input_refs[index];
        let tokens = &self.credentials.reads[index];
        let scope = Bytes::from(canonical(&json!({
            "schema_version": "1", "attempt": ctx.attempt, "manifest_digest": reference.manifest_digest,
        }))?);
        ctx.check()?;
        let raw = binary(
            self.fabric
                .call(
                    "POST",
                    "/v1/compute-inputs/manifest",
                    tokens.first().ok_or("UNAVAILABLE")?,
                    scope.clone(),
                    200,
                    CONTROL,
                )
                .await?,
            None,
        )?;
        let manifest: Value = serde_json::from_slice(&raw).map_err(|_| "INVALID_REQUEST")?;
        manifest_schema(&manifest)?;
        let size = number(&manifest["serialized_bytes"])?;
        if canonical(&manifest)? != raw
            || digest(b"kryvola/manifest/v2\0", &[&raw]) != reference.manifest_digest
            || manifest["tenant_scope"] != reference.tenant_scope
            || manifest["artifact_kind"] != kind
            || manifest["key_context_digest"]
                != ctx.operation["key_context_ref"]["key_context_digest"]
            || manifest["native_codec_version"] != NATIVE_CODEC
            || manifest["parameters"]
                != json!({"scheme":"TFHE","parameter_set_digest":PARAMETERS,
                "radix_bits":"8","message_modulus":"4","carry_modulus":"4"})
            || manifest["precision"]
                != json!({"dtype":"uint8","fractional_bits":"0","overflow":"WRAP"})
            || (kind == "CIPHERTEXT" && manifest["shape"] != json!(["2"]))
            || !(1..=max).contains(&size)
            || reference.byte_length != size.to_string()
        {
            return Err("INVALID_REQUEST");
        }
        let entries = manifest["ordered_chunk_entries"]
            .as_array()
            .ok_or("INVALID_REQUEST")?;
        if entries.len() + 1 != tokens.len() {
            return Err("UNAVAILABLE");
        }
        let mut data = Vec::with_capacity(size);
        for (index, entry) in entries.iter().enumerate() {
            let length = number(&entry["byte_length"])?;
            if !(1..=PART_MAX).contains(&length)
                || length > size - data.len()
                || number(&entry["index"])? != index
                || number(&entry["byte_offset"])? != data.len()
            {
                return Err("INVALID_REQUEST");
            }
            ctx.check()?;
            let part = binary(
                self.fabric
                    .call(
                        "POST",
                        &format!("/v1/compute-inputs/parts/{index}"),
                        &tokens[index + 1],
                        scope.clone(),
                        200,
                        length,
                    )
                    .await?,
                Some(length),
            )?;
            if entry["chunk_digest"]
                != digest(
                    b"kryvola/chunk/v1\0",
                    &[
                        &(index as u64).to_le_bytes(),
                        &(length as u64).to_le_bytes(),
                        &part,
                    ],
                )
            {
                return Err("INVALID_REQUEST");
            }
            data.extend_from_slice(&part);
        }
        let digest = digest(b"kryvola/blob/v1\0", &[&data]);
        if data.len() != size || manifest["full_blob_digest"] != digest {
            return Err("INVALID_REQUEST");
        }
        std::fs::write(path, data).map_err(|_| "UNAVAILABLE")?;
        Ok(Input { manifest, digest })
    }

    async fn issue(&self, ctx: &Run<'_>, digest: &str, target: Value) -> Result<String> {
        ctx.check()?;
        let response = self.fabric.call("POST", "/v1/executions/output-grants", &self.credentials.output,
            canonical(&json!({"schema_version":"1","attempt":ctx.attempt,"execution_id":ctx.execution_id,
                "manifest_digest":digest,"target":target}))?.into(), 200, CONTROL).await?;
        let metadata: Value = serde_json::from_slice(&response.body).map_err(|_| "UNAVAILABLE")?;
        let now = now();
        if metadata.as_object().is_none_or(|fields| fields.len() != 2)
            || metadata["schema_version"] != "1"
            || !metadata["expires_unix_ms"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|expiry| {
                    (now.saturating_add(1)..=now.saturating_add(60_000)).contains(&expiry)
                })
            || response
                .headers
                .get("cache-control")
                .and_then(|value| value.to_str().ok())
                != Some("no-store")
        {
            return Err("UNAVAILABLE");
        }
        let grant = response
            .headers
            .get("kryvola-output-grant")
            .and_then(|v| v.to_str().ok())
            .filter(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            .ok_or("UNAVAILABLE")?;
        Ok(grant.into())
    }

    async fn publish(
        &self,
        ctx: &Run<'_>,
        mut manifest: Value,
        data: Vec<u8>,
    ) -> Result<ArtifactRef> {
        let size = data.len();
        if !(1..=PAIR_MAX).contains(&size) {
            return Err("INVALID_REQUEST");
        }
        manifest["producer_identity"] = json!(self.receipt.signer);
        manifest["shape"] = json!(["2"]);
        manifest["serialized_bytes"] = json!(size.to_string());
        manifest["max_expanded_bytes"] = json!(PAIR_MAX.to_string());
        manifest["full_blob_digest"] = json!(digest(b"kryvola/blob/v1\0", &[&data]));
        manifest["ordered_chunk_entries"] = json!([{"index":"0","byte_offset":"0","byte_length":size.to_string(),
            "chunk_digest":digest(b"kryvola/chunk/v1\0", &[&0u64.to_le_bytes(), &(size as u64).to_le_bytes(), &data])}]);
        manifest_schema(&manifest)?;
        let raw = canonical(&manifest)?;
        let output = digest(b"kryvola/manifest/v2\0", &[&raw]);
        let tenant = ctx.attempt["tenant_scope"]
            .as_str()
            .ok_or("INVALID_REQUEST")?;
        let grant = self
            .issue(ctx, &output, json!({"action":"RESERVE"}))
            .await?;
        let reserved = self
            .fabric
            .call(
                "POST",
                "/v1/uploads",
                &grant,
                canonical(&json!({"schema_version":"1","tenant_scope":tenant,"byte_length":size}))?
                    .into(),
                201,
                CONTROL,
            )
            .await?;
        let reserved: Value = serde_json::from_slice(&reserved.body).map_err(|_| "UNAVAILABLE")?;
        let id = reserved["upload_id"]
            .as_str()
            .filter(|id| {
                id.len() == 32
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            .ok_or("UNAVAILABLE")?;
        let grant = self
            .issue(
                ctx,
                &output,
                json!({"action":"PUT_PART","upload_id":id,"part_index":0}),
            )
            .await?;
        self.fabric
            .call(
                "PUT",
                &format!("/v1/uploads/{id}/parts/0"),
                &grant,
                data.into(),
                204,
                0,
            )
            .await?;
        let grant = self
            .issue(
                ctx,
                &output,
                json!({"action":"PUT_MANIFEST","upload_id":id}),
            )
            .await?;
        self.fabric
            .call(
                "PUT",
                &format!("/v1/uploads/{id}/manifest"),
                &grant,
                raw.into(),
                204,
                0,
            )
            .await?;
        let grant = self
            .issue(ctx, &output, json!({"action":"FINALIZE","upload_id":id}))
            .await?;
        let reply = self
            .fabric
            .call(
                "POST",
                &format!("/v1/uploads/{id}/finalize"),
                &grant,
                canonical(
                    &json!({"schema_version":"1","tenant_scope":tenant,"manifest_digest":output}),
                )?
                .into(),
                200,
                CONTROL,
            )
            .await?;
        let value: Value = serde_json::from_slice(&reply.body).map_err(|_| "UNAVAILABLE")?;
        if value != json!({"schema_version":"1","manifest_digest":output}) {
            return Err("UNAVAILABLE");
        }
        self.persist_receipt(ctx, id, &output).await?;
        Ok(ArtifactRef {
            opaque_artifact_id: id.into(),
            tenant_scope: tenant.into(),
            immutable_version: "1".into(),
            manifest_digest: output,
            byte_length: size.to_string(),
            media_type: MEDIA.into(),
            schema_version: "1".into(),
        })
    }

    async fn persist_receipt(&self, ctx: &Run<'_>, upload: &str, output: &str) -> Result<()> {
        ctx.check()?;
        let op = &ctx.operation;
        let policy = &self.receipt;
        let payload = json!({
            "schema_version":"3","object_type":"receipt","assurance":"CONFIDENTIALITY_ONLY",
            "tenant_scope":op["tenant_scope"],"logical_job_id":op["logical_job_id"],"operation_id":op["operation_id"],
            "stage_id":op["stage_id"],"plan_digest":op["plan_ref"]["plan_digest"],
            "key_context_digest":op["key_context_ref"]["key_context_digest"],"policy_digest":op["policy_digest"],
            "workflow_epoch":ctx.attempt["workflow_epoch"],"attempt_epoch":ctx.attempt["attempt_epoch"],
            "fence":ctx.attempt["fence"],"execution_id":ctx.execution_id,"session_epoch":"0",
            "engine_digest":ctx.request.engine_digest,"program_digest":PROGRAM,
            "input_manifest_digests":ctx.request.input_refs.iter().map(|r| &r.manifest_digest).collect::<Vec<_>>(),
            "output_manifest_digests":[output],"policy_epoch":policy.policy_epoch,
            "consent_digest":policy.consent_digest,"model_digest":policy.model_digest,
            "capability_profile_digest":policy.capability_profile_digest,"leakage_profile_digest":policy.leakage_profile_digest,
            "evidence_policy_digest":policy.evidence_policy_digest,"evidence_journal_digests":[],
            "evidence_status":"NOT_REQUESTED","signer":policy.signer,
            "started_unix_ms":ctx.started.to_string(),"completed_unix_ms":now().to_string(),
        });
        static SCHEMA: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
        validate(
            &payload,
            include_str!("../../../contracts/spec/canonical/v3/receipt.schema.json"),
            &SCHEMA,
        )?;
        let payload = canonical(&payload)?;
        let commitment = digest(b"kryvola/receipt/v3\0", &[&payload]);
        let mut envelope = json!({"schema_version":"3","algorithm":"Ed25519","payload_kind":"receipt",
            "payload_digest":commitment,"signer":policy.signer,"key_id":policy.key_id,"key_epoch":policy.key_epoch});
        let mut preimage = b"kryvola/signature/receipt/v3\0".to_vec();
        for bytes in [&canonical(&envelope)?, &payload] {
            preimage.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            preimage.extend_from_slice(bytes);
        }
        envelope["signature"] = json!(URL_SAFE_NO_PAD.encode(self.key.sign(&preimage).as_ref()));
        let response = self.fabric.call("POST", "/v1/executions/receipt", &self.credentials.receipt,
            canonical(&json!({"schema_version":"1","attempt":ctx.attempt,"execution_id":ctx.execution_id,
                "output_upload_id":upload,"receipt_base64url":URL_SAFE_NO_PAD.encode(payload),
                "signature_base64url":URL_SAFE_NO_PAD.encode(canonical(&envelope)?)}))?.into(), 200, CONTROL).await?;
        let body: Value = serde_json::from_slice(&response.body).map_err(|_| "UNAVAILABLE")?;
        if body != json!({"schema_version":"1","receipt_digest":commitment}) {
            return Err("UNAVAILABLE");
        }
        Ok(())
    }
}

struct Run<'a> {
    request: &'a ExecuteRequest,
    operation: Value,
    attempt: Value,
    execution_id: &'a str,
    started: u64,
    deadline: std::time::Instant,
    stop: &'a AtomicBool,
}

impl Run<'_> {
    fn check(&self) -> Result<()> {
        if self.stop.load(Ordering::Acquire) {
            return Err("CANCELLED");
        }
        if std::time::Instant::now() >= self.deadline {
            return Err("DEADLINE_EXCEEDED");
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl<F: Fabric> Evaluation for Pipeline<F> {
    async fn run(&self, request: &ExecuteRequest, stop: &AtomicBool) -> Result<ArtifactRef> {
        let ex = request.execution.as_ref().ok_or("INVALID_REQUEST")?;
        let started = now();
        let deadline = ex
            .deadline_unix_ms
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or("INVALID_REQUEST")?;
        let ctx = Run {
            request,
            stop,
            started,
            deadline: std::time::Instant::now()
                + std::time::Duration::from_millis(deadline.saturating_sub(started).min(60_000)),
            execution_id: ex.execution_id.as_deref().ok_or("INVALID_REQUEST")?,
            operation: codec::to_json(request.operation.as_ref().ok_or("INVALID_REQUEST")?)
                .map_err(|_| "INVALID_REQUEST")?,
            attempt: codec::to_json(ex.attempt.as_ref().ok_or("INVALID_REQUEST")?)
                .map_err(|_| "INVALID_REQUEST")?,
        };
        let scratch = tempfile::tempdir().map_err(|_| "UNAVAILABLE")?;
        let [key, input, output] = ["key", "input", "output"].map(|name| scratch.path().join(name));
        let key_artifact = self.fetch(&ctx, 0, &key).await?;
        let input_artifact = self.fetch(&ctx, 1, &input).await?;
        ctx.check()?;
        let status = tokio::process::Command::new("/usr/bin/python3")
            .arg("-I")
            .arg(&self.supervisor)
            .arg(&self.evaluator)
            .args([&key, &input, &output])
            .args([&key_artifact.digest, &input_artifact.digest, PROGRAM])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map_err(|_| "UNAVAILABLE")?;
        if !status.success() {
            return Err("UNAVAILABLE");
        }
        let metadata = std::fs::symlink_metadata(&output).map_err(|_| "UNAVAILABLE")?;
        if !metadata.is_file() || metadata.len() > PAIR_MAX as u64 {
            return Err("UNAVAILABLE");
        }
        let data = std::fs::read(output).map_err(|_| "UNAVAILABLE")?;
        self.publish(&ctx, input_artifact.manifest, data).await
    }
}

#[cfg(test)]
mod tests;
