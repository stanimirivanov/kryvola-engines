//! Single-assignment artifact-backed CPU Engine service.
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{SystemTime, UNIX_EPOCH};

use kryvola_engine_api::wire::{engine_service_server::EngineService, *};
use tonic::{Request, Response, Status};

pub const PROGRAM: &str = "52687303e4a13081f0f40c15bfa0fafbf35812fb96a3d30f99206ee534c010f5";
pub const PARAMETERS: &str = "cda9e129d55cc6a17060d8913f6e0d554c5a990e62c967514db86bf57a524674";

pub fn admit(approved: &ExecuteRequest, request: &ExecuteRequest) -> Result<(), Status> {
    if approved != request {
        return Err(Status::permission_denied("UNAPPROVED_EXECUTION"));
    }
    let op = request
        .operation
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("CONTEXT"))?;
    let ex = request
        .execution
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("CONTEXT"))?;
    let attempt = ex
        .attempt
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("CONTEXT"))?;
    if request.program_digest.as_deref() != Some(PROGRAM)
        || request.parameter_set_digest.as_deref() != Some(PARAMETERS)
        || request.security_profile.as_deref() != Some("FHE-Q1")
        || request.required_operators.len() != 2
        || !["ADD", "MUL"]
            .iter()
            .all(|op| request.required_operators.iter().any(|v| v == op))
    {
        return Err(Status::failed_precondition("UNSUPPORTED_PROFILE"));
    }
    if attempt.tenant_scope != op.tenant_scope
        || attempt.operation_id != op.operation_id
        || attempt.workflow_epoch != op.workflow_epoch
        || ex.deadline_unix_ms != op.deadline_unix_ms
        || ex.session_epoch.as_deref() != Some("0")
        || ex.physical_state.as_deref() != Some("CREATED")
        || request.input_refs.len() != 2
        || request.input_refs[0].manifest_digest == request.input_refs[1].manifest_digest
        || request
            .input_refs
            .iter()
            .any(|r| Some(&r.tenant_scope) != op.tenant_scope.as_ref())
        || op
            .plan_ref
            .as_ref()
            .is_none_or(|r| r.tenant_scope != op.tenant_scope)
        || op
            .key_context_ref
            .as_ref()
            .is_none_or(|r| r.tenant_scope != op.tenant_scope)
    {
        return Err(Status::invalid_argument("CONTEXT"));
    }
    Ok(())
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(u64::MAX)
}

#[tonic::async_trait]
pub trait Evaluation: Send + Sync + 'static {
    async fn run(
        &self,
        request: &ExecuteRequest,
        stop: &AtomicBool,
    ) -> Result<ArtifactRef, &'static str>;
}

struct Observation {
    execution: Execution,
    output: Option<ArtifactRef>,
    error: &'static str,
    cancellation: Option<String>,
}

pub struct Engine<E> {
    request: Arc<ExecuteRequest>,
    evaluator: Arc<E>,
    observation: Arc<Mutex<Observation>>,
    stop: Arc<AtomicBool>,
}

impl<E: Evaluation> Engine<E> {
    pub fn new(request: ExecuteRequest, evaluator: E) -> Result<Self, Status> {
        admit(&request, &request)?;
        let execution = request
            .execution
            .clone()
            .ok_or_else(|| Status::invalid_argument("CONTEXT"))?;
        Ok(Self {
            request: Arc::new(request),
            evaluator: Arc::new(evaluator),
            observation: Arc::new(Mutex::new(Observation {
                execution,
                output: None,
                error: "NONE",
                cancellation: None,
            })),
            stop: Arc::default(),
        })
    }

    fn matches(&self, attempt: &Option<Attempt>, id: &Option<String>) -> bool {
        self.request
            .execution
            .as_ref()
            .is_some_and(|ex| &ex.attempt == attempt && &ex.execution_id == id)
    }
}

#[tonic::async_trait]
impl<E: Evaluation> EngineService for Engine<E> {
    async fn get_capabilities(
        &self,
        _: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        Ok(Response::new(GetCapabilitiesResponse {
            schema_version: Some("1".into()),
            capabilities: Some(Capabilities {
                schema_version: Some("1".into()),
                engine_digest: self.request.engine_digest.clone(),
                parameter_set_digest: Some(PARAMETERS.into()),
                program_digests: vec![PROGRAM.into()],
                security_profiles: vec!["FHE-Q1".into()],
                operators: vec!["ADD".into(), "MUL".into()],
                arithmetic: Some("EXACT_MODULAR".into()),
                max_parallel_executions: Some("1".into()),
            }),
        }))
    }

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<ExecuteResponse>, Status> {
        admit(&self.request, request.get_ref())?;
        let mut row = self
            .observation
            .lock()
            .map_err(|_| Status::internal("STATE"))?;
        if row.execution.physical_state.as_deref() == Some("CREATED") {
            row.execution
                .deadline_unix_ms
                .as_deref()
                .and_then(|n| n.parse::<u64>().ok())
                .filter(|deadline| *deadline > now())
                .ok_or_else(|| Status::deadline_exceeded("EXPIRED"))?;
            row.execution.physical_state = Some("RUNNING".into());
            let (evaluator, approved, observation, stop) = (
                self.evaluator.clone(),
                self.request.clone(),
                self.observation.clone(),
                self.stop.clone(),
            );
            tokio::spawn(async move {
                let result = evaluator.run(&approved, &stop).await;
                if let Ok(mut row) = observation.lock() {
                    let state = match result {
                        Ok(output) => {
                            row.output = Some(output);
                            "SUCCEEDED"
                        }
                        Err(reason) => {
                            row.error = reason;
                            match reason {
                                "CANCELLED" => "CANCELLED",
                                "DEADLINE_EXCEEDED" => "EXPIRED",
                                _ => "FAILED",
                            }
                        }
                    };
                    row.execution.physical_state = Some(state.into());
                }
            });
        }
        Ok(Response::new(ExecuteResponse {
            schema_version: Some("1".into()),
            execution: Some(row.execution.clone()),
        }))
    }

    async fn get_execution_status(
        &self,
        request: Request<GetExecutionStatusRequest>,
    ) -> Result<Response<GetExecutionStatusResponse>, Status> {
        let request = request.get_ref();
        if !self.matches(&request.attempt, &request.execution_id) {
            return Err(Status::not_found("UNKNOWN_EXECUTION"));
        }
        let row = self
            .observation
            .lock()
            .map_err(|_| Status::internal("STATE"))?;
        Ok(Response::new(GetExecutionStatusResponse {
            schema_version: Some("1".into()),
            execution: Some(row.execution.clone()),
            output_refs: row.output.clone().into_iter().collect(),
            error_code: Some(row.error.into()),
        }))
    }

    async fn cancel_execution(
        &self,
        request: Request<CancelExecutionRequest>,
    ) -> Result<Response<CancelExecutionResponse>, Status> {
        let request = request.into_inner();
        let state = if !self.matches(&request.attempt, &request.execution_id) {
            "NOT_FOUND"
        } else {
            let mut row = self
                .observation
                .lock()
                .map_err(|_| Status::internal("STATE"))?;
            if row.cancellation.is_some() && row.cancellation != request.cancellation_id {
                return Err(Status::already_exists("CANCELLATION_CONFLICT"));
            }
            row.cancellation = request.cancellation_id.clone();
            self.stop.store(true, Ordering::Release);
            match row.execution.physical_state.as_deref() {
                Some("CREATED") => {
                    row.execution.physical_state = Some("CANCELLED".into());
                    row.error = "CANCELLED";
                    "OBSERVED_STOPPED"
                }
                Some("RUNNING") => "REQUESTED",
                _ => "OBSERVED_STOPPED",
            }
        };
        Ok(Response::new(CancelExecutionResponse {
            schema_version: Some("1".into()),
            attempt: request.attempt,
            execution_id: request.execution_id,
            cancellation_id: request.cancellation_id,
            cancellation_state: Some(state.into()),
        }))
    }
}
