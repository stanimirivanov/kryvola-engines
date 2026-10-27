//! Test-only state machine. No inference, crypto, artifact access or production registration.
extern crate self as tonic_prost;
pub mod codec;
pub mod conformance;
pub use codec::ProstCodec;
pub mod wire {
    include!("../../../contracts/native/rust/kryvola.spec.v1.rs");
}
use std::{
    collections::{HashMap, hash_map::Entry},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};
use tonic::{Request, Response, Status};
use wire::{engine_service_server::EngineService, *};

pub const FAKE_ENGINE_DIGEST: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    attempt: Attempt,
    execution_id: String,
}
fn key(attempt: Option<Attempt>, execution_id: Option<String>) -> Result<Key, Status> {
    Ok(Key {
        attempt: attempt.ok_or_else(|| Status::invalid_argument("INVALID_CONTEXT"))?,
        execution_id: execution_id.ok_or_else(|| Status::invalid_argument("INVALID_CONTEXT"))?,
    })
}
struct Row {
    original: Option<ExecuteRequest>,
    execution: Option<Execution>,
    polls: u8,
    ordinal: usize,
}
#[derive(Clone)]
pub struct FakeEngine {
    rows: Arc<Mutex<HashMap<Key, Row>>>,
    now: Arc<AtomicU64>,
    capacity: usize,
    caps: Capabilities,
}
fn marked<T>(value: T) -> Response<T> {
    let mut r = Response::new(value);
    r.metadata_mut()
        .insert("x-kryvola-fake", "true".parse().expect("static marker"));
    r
}
fn expire(row: &mut Row, now: u64) {
    if let Some(ex) = row.execution.as_mut()
        && ex.physical_state.as_deref() == Some("RUNNING")
        && ex
            .deadline_unix_ms
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .is_some_and(|d| now >= d)
    {
        ex.physical_state = Some("EXPIRED".into());
    }
}
impl FakeEngine {
    pub fn new(capacity: usize, now: Arc<AtomicU64>) -> Result<Self, Status> {
        if !(1..=64).contains(&capacity) {
            return Err(Status::invalid_argument("INVALID_CAPACITY"));
        }
        let mut caps: Capabilities = codec::fixture("Capabilities");
        caps.engine_digest = Some(FAKE_ENGINE_DIGEST.into());
        caps.max_parallel_executions = Some(capacity.to_string());
        Ok(Self {
            rows: Arc::default(),
            now,
            capacity,
            caps,
        })
    }
}
#[tonic::async_trait]
impl EngineService for FakeEngine {
    async fn get_capabilities(
        &self,
        _: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(marked(GetCapabilitiesResponse {
            schema_version: Some("1".into()),
            capabilities: Some(self.caps.clone()),
        }))
    }
    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        let q = request.into_inner();
        let op = q
            .operation
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("INVALID_CONTEXT"))?;
        let mut ex = q
            .execution
            .clone()
            .ok_or_else(|| Status::invalid_argument("INVALID_CONTEXT"))?;
        let k = key(ex.attempt.clone(), ex.execution_id.clone())?;
        if op.tenant_scope != k.attempt.tenant_scope
            || op.operation_id != k.attempt.operation_id
            || op.workflow_epoch != k.attempt.workflow_epoch
            || op.deadline_unix_ms != ex.deadline_unix_ms
            || op
                .plan_ref
                .as_ref()
                .is_none_or(|r| r.tenant_scope != op.tenant_scope)
            || op
                .key_context_ref
                .as_ref()
                .is_none_or(|r| r.tenant_scope != op.tenant_scope)
            || op.disclosure_identity.as_ref().is_none_or(|r| {
                r.tenant_scope != op.tenant_scope || r.logical_job_id != op.logical_job_id
            })
            || q.input_refs
                .iter()
                .any(|r| Some(r.tenant_scope.as_str()) != op.tenant_scope.as_deref())
            || ex.physical_state.as_deref() != Some("CREATED")
        {
            return Err(Status::invalid_argument("INVALID_CONTEXT"));
        }
        if q.engine_digest != self.caps.engine_digest
            || q.parameter_set_digest != self.caps.parameter_set_digest
            || q.program_digest
                .as_ref()
                .is_none_or(|p| !self.caps.program_digests.contains(p))
            || !self
                .caps
                .security_profiles
                .iter()
                .any(|p| Some(p) == q.security_profile.as_ref())
            || q.required_operators
                .iter()
                .any(|p| !self.caps.operators.contains(p))
            || q.required_operators
                .iter()
                .enumerate()
                .any(|(i, p)| q.required_operators[..i].contains(p))
        {
            return Err(Status::failed_precondition("UNSUPPORTED_CAPABILITY"));
        }
        let mut rows = self.rows.lock().map_err(|_| Status::internal("STATE"))?;
        let now = self.now.load(Ordering::SeqCst);
        if let Some(row) = rows.get_mut(&k) {
            if row.original.is_none() {
                return Err(Status::cancelled("CANCELLED"));
            }
            if row.original.as_ref() != Some(&q) {
                return Err(Status::already_exists("INTENT_CONFLICT"));
            }
            expire(row, now);
            return Ok(marked(ExecuteResponse {
                schema_version: Some("1".into()),
                execution: row.execution.clone(),
            }));
        }
        if ex
            .deadline_unix_ms
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .is_none_or(|d| now >= d)
        {
            return Err(Status::deadline_exceeded("EXPIRED"));
        }
        if rows.len() >= self.capacity {
            return Err(Status::resource_exhausted("CAPACITY"));
        }
        ex.physical_state = Some("RUNNING".into());
        let ordinal = rows.len() + 1;
        rows.insert(
            k,
            Row {
                original: Some(q),
                execution: Some(ex.clone()),
                polls: 0,
                ordinal,
            },
        );
        Ok(marked(ExecuteResponse {
            schema_version: Some("1".into()),
            execution: Some(ex),
        }))
    }
    async fn get_execution_status(
        &self,
        request: Request<GetExecutionStatusRequest>,
    ) -> Result<Response<GetExecutionStatusResponse>, Status> {
        let q = request.into_inner();
        let k = key(q.attempt, q.execution_id)?;
        let mut rows = self.rows.lock().map_err(|_| Status::internal("STATE"))?;
        let row = rows
            .get_mut(&k)
            .ok_or_else(|| Status::not_found("NOT_FOUND"))?;
        expire(row, self.now.load(Ordering::SeqCst));
        let ex = row
            .execution
            .as_mut()
            .ok_or_else(|| Status::not_found("NOT_FOUND"))?;
        if ex.physical_state.as_deref() == Some("RUNNING") {
            row.polls += 1;
            if row.polls == 2 {
                ex.physical_state = Some("SUCCEEDED".into());
            }
        }
        let state = ex.physical_state.as_deref().unwrap_or("");
        let error = match state {
            "EXPIRED" => "DEADLINE_EXCEEDED",
            "CANCELLED" => "CANCELLED",
            _ => "NONE",
        };
        let refs = if state == "SUCCEEDED" {
            vec![ArtifactRef {
                schema_version: "1".into(),
                opaque_artifact_id: format!("fake-output-{}", row.ordinal),
                tenant_scope: k.attempt.tenant_scope.unwrap_or_default(),
                immutable_version: "fake-only".into(),
                manifest_digest: FAKE_ENGINE_DIGEST.into(),
                byte_length: "0".into(),
                media_type: "application/vnd.kryvola.tfhe-ciphertext".into(),
            }]
        } else {
            vec![]
        };
        Ok(marked(GetExecutionStatusResponse {
            schema_version: Some("1".into()),
            execution: Some(ex.clone()),
            output_refs: refs,
            error_code: Some(error.into()),
        }))
    }
    async fn cancel_execution(
        &self,
        request: Request<CancelExecutionRequest>,
    ) -> Result<Response<CancelExecutionResponse>, Status> {
        let q = request.into_inner();
        let k = key(q.attempt.clone(), q.execution_id.clone())?;
        let mut rows = self.rows.lock().map_err(|_| Status::internal("STATE"))?;
        let full = rows.len() >= self.capacity;
        let row = match rows.entry(k) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                if full {
                    return Err(Status::resource_exhausted("CAPACITY"));
                }
                entry.insert(Row {
                    original: None,
                    execution: None,
                    polls: 0,
                    ordinal: 0,
                })
            }
        };
        expire(row, self.now.load(Ordering::SeqCst));
        let state = if let Some(ex) = row.execution.as_mut() {
            if ex.physical_state.as_deref() == Some("RUNNING") {
                ex.physical_state = Some("CANCELLED".into());
            }
            "OBSERVED_STOPPED"
        } else {
            "NOT_FOUND"
        };
        Ok(marked(CancelExecutionResponse {
            schema_version: Some("1".into()),
            attempt: q.attempt,
            execution_id: q.execution_id,
            cancellation_id: q.cancellation_id,
            cancellation_state: Some(state.into()),
        }))
    }
}
