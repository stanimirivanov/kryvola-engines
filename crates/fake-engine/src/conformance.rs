//! Bounded real loopback RPC exercise; no deployed service or external artifact dependency.
use crate::{
    FAKE_ENGINE_DIGEST, FakeEngine, codec,
    wire::{
        self, engine_service_client::EngineServiceClient,
        engine_service_server::EngineServiceServer,
    },
};
use bytes::{Buf, BufMut};
use prost::Message;
use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::oneshot};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{
    Code, Request, Status,
    codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder},
    transport::{Channel, Endpoint, Server},
};

pub fn request(id: &str) -> wire::ExecuteRequest {
    let mut q: wire::ExecuteRequest = codec::fixture("ExecuteRequest");
    q.engine_digest = Some(FAKE_ENGINE_DIGEST.into());
    q.execution.as_mut().expect("fixture").execution_id = Some(id.into());
    q
}
fn target(q: &wire::ExecuteRequest) -> wire::GetExecutionStatusRequest {
    let ex = q.execution.as_ref().expect("fixture");
    wire::GetExecutionStatusRequest {
        schema_version: Some("1".into()),
        attempt: ex.attempt.clone(),
        execution_id: ex.execution_id.clone(),
    }
}
fn cancel(q: &wire::ExecuteRequest) -> wire::CancelExecutionRequest {
    let t = target(q);
    wire::CancelExecutionRequest {
        schema_version: t.schema_version,
        attempt: t.attempt,
        execution_id: t.execution_id,
        cancellation_id: Some("fake-cancel".into()),
    }
}
fn state(r: &wire::GetExecutionStatusResponse) -> &str {
    r.execution
        .as_ref()
        .and_then(|e| e.physical_state.as_deref())
        .expect("execution state")
}

// An independent raw client deliberately bypasses the typed client's outbound validation.
#[derive(Clone, Default)]
struct Raw;
impl Codec for Raw {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = Self;
    type Decoder = Self;
    fn encoder(&mut self) -> Self {
        Self
    }
    fn decoder(&mut self) -> Self {
        Self
    }
}
impl Encoder for Raw {
    type Item = Vec<u8>;
    type Error = Status;
    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        dst.put_slice(&item);
        Ok(())
    }
}
impl Decoder for Raw {
    type Item = Vec<u8>;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
        Ok(Some(src.copy_to_bytes(src.remaining()).to_vec()))
    }
}
async fn rejected(
    channel: Channel,
    path: &'static str,
    bytes: Vec<u8>,
    expected: &[Code],
) -> Result<(), Box<dyn Error>> {
    let mut client = tonic::client::Grpc::new(channel).max_decoding_message_size(65536);
    client
        .ready()
        .await
        .map_err(|_| std::io::Error::other("CLIENT_NOT_READY"))?;
    let result = client
        .unary(
            Request::new(bytes),
            tonic::codegen::http::uri::PathAndQuery::from_static(path),
            Raw,
        )
        .await;
    let error = result.expect_err("raw invalid request must fail at the remote boundary");
    assert!(
        expected.contains(&error.code()),
        "unexpected safe status: {:?}",
        error.code()
    );
    assert!(!error.message().contains("SECRET_X"));
    Ok(())
}
async fn checks(channel: Channel, now: Arc<AtomicU64>) -> Result<(), Box<dyn Error>> {
    let mut client = EngineServiceClient::new(channel.clone());
    let caps = client
        .get_capabilities(wire::GetCapabilitiesRequest {
            schema_version: Some("1".into()),
        })
        .await?;
    assert_eq!(
        caps.metadata()
            .get("x-kryvola-fake")
            .expect("fake marker")
            .to_str()?,
        "true"
    );
    assert_eq!(
        caps.into_inner()
            .capabilities
            .expect("caps")
            .engine_digest
            .as_deref(),
        Some(FAKE_ENGINE_DIGEST)
    );
    let q = request("complete");
    let mut duplicate = client.clone();
    let (first, concurrent) = tokio::join!(client.execute(q.clone()), duplicate.execute(q.clone()));
    let first = first?.into_inner();
    assert_eq!(concurrent?.into_inner(), first);
    assert_eq!(client.execute(q.clone()).await?.into_inner(), first);
    let mut conflict = q.clone();
    conflict.output_contract_digest = Some("a".repeat(64));
    assert_eq!(
        client
            .execute(conflict)
            .await
            .expect_err("intent conflict")
            .code(),
        Code::AlreadyExists
    );
    assert_eq!(
        state(&client.get_execution_status(target(&q)).await?.into_inner()),
        "RUNNING"
    );
    let done = client.get_execution_status(target(&q)).await?.into_inner();
    assert_eq!(state(&done), "SUCCEEDED");
    assert!(
        done.output_refs[0]
            .opaque_artifact_id
            .starts_with("fake-output-")
    );
    client.cancel_execution(cancel(&q)).await?;
    assert_eq!(
        client.get_execution_status(target(&q)).await?.into_inner(),
        done
    );

    let q = request("cancel-before-submit");
    let cancelled = client.cancel_execution(cancel(&q)).await?.into_inner();
    assert_eq!(
        client.cancel_execution(cancel(&q)).await?.into_inner(),
        cancelled
    );
    assert_eq!(
        client
            .execute(q)
            .await
            .expect_err("cancel tombstone")
            .code(),
        Code::Cancelled
    );
    let q = request("race");
    client.execute(q.clone()).await?;
    client.get_execution_status(target(&q)).await?;
    let mut other = client.clone();
    let (poll, stop) = tokio::join!(
        client.get_execution_status(target(&q)),
        other.cancel_execution(cancel(&q))
    );
    poll?;
    stop?;
    let terminal = client.get_execution_status(target(&q)).await?.into_inner();
    assert!(["CANCELLED", "SUCCEEDED"].contains(&state(&terminal)));
    assert_eq!(
        client.get_execution_status(target(&q)).await?.into_inner(),
        terminal
    );

    let mut q = request("expire");
    q.operation.as_mut().expect("op").deadline_unix_ms = Some("5".into());
    q.execution.as_mut().expect("execution").deadline_unix_ms = Some("5".into());
    client.execute(q.clone()).await?;
    now.store(5, Ordering::SeqCst);
    assert_eq!(
        state(&client.get_execution_status(target(&q)).await?.into_inner()),
        "EXPIRED"
    );
    assert_eq!(
        client
            .execute(q.clone())
            .await?
            .into_inner()
            .execution
            .expect("execution")
            .physical_state
            .as_deref(),
        Some("EXPIRED")
    );
    q.execution.as_mut().expect("execution").execution_id = Some("late".into());
    assert_eq!(
        client.execute(q).await.expect_err("deadline").code(),
        Code::DeadlineExceeded
    );
    let mut q = request("unsupported");
    q.security_profile = Some("FHE-A1".into());
    assert_eq!(
        client.execute(q).await.expect_err("profile").code(),
        Code::FailedPrecondition
    );
    for field in 0..3 {
        let mut q = request("unsupported-pin");
        match field {
            0 => q.engine_digest = Some("a".repeat(64)),
            1 => q.parameter_set_digest = Some("a".repeat(64)),
            _ => q.program_digest = Some("a".repeat(64)),
        }
        assert_eq!(
            client.execute(q).await.expect_err("unsupported pin").code(),
            Code::FailedPrecondition
        );
    }
    let mut q = request("context");
    q.input_refs[0].tenant_scope = "other".into();
    assert_eq!(
        client.execute(q).await.expect_err("tenant").code(),
        Code::InvalidArgument
    );

    const CAPS: &str = "/kryvola.spec.v1.EngineService/GetCapabilities";
    const EXECUTE: &str = "/kryvola.spec.v1.EngineService/Execute";
    for bytes in [
        vec![],
        b"\x0a\x01\x32".to_vec(),
        b"\x0a\x01\x31\xf8\x1f\x01".to_vec(),
        b"\xffSECRET_X".to_vec(),
    ] {
        rejected(channel.clone(), CAPS, bytes, &[Code::InvalidArgument]).await?;
    }
    let mut bad = request("bad-ref");
    bad.input_refs[0].manifest_digest = "SECRET_X".into();
    rejected(
        channel.clone(),
        EXECUTE,
        bad.encode_to_vec(),
        &[Code::InvalidArgument],
    )
    .await?;
    let mut bad = request("bad-nested").encode_to_vec();
    bad.extend_from_slice(b"\x1a\x0b\xfa\x1f\x08SECRET_X");
    rejected(channel.clone(), EXECUTE, bad, &[Code::InvalidArgument]).await?;
    rejected(
        channel.clone(),
        EXECUTE,
        vec![0; 65537],
        &[Code::OutOfRange, Code::ResourceExhausted],
    )
    .await?;
    rejected(
        channel,
        "/kryvola.spec.v1.EngineService/Decrypt",
        vec![],
        &[Code::Unimplemented],
    )
    .await?;
    for n in 0..4 {
        client.execute(request(&format!("fill-{n}"))).await?;
    }
    assert_eq!(
        client
            .execute(request("overflow"))
            .await
            .expect_err("capacity")
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        client
            .cancel_execution(cancel(&request("new-tombstone")))
            .await
            .expect_err("capacity")
            .code(),
        Code::ResourceExhausted
    );
    assert_eq!(
        client
            .execute(request("complete"))
            .await?
            .into_inner()
            .execution
            .expect("execution")
            .physical_state
            .as_deref(),
        Some("SUCCEEDED")
    );
    Ok(())
}
pub async fn run() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let now = Arc::new(AtomicU64::new(0));
    let engine = FakeEngine::new(8, now.clone())?;
    let service = EngineServiceServer::new(engine)
        .max_decoding_message_size(65536)
        .max_encoding_message_size(65536);
    let (stop, stopped) = oneshot::channel();
    let mut server = tokio::spawn(async move {
        Server::builder()
            .add_service(service)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                let _ = stopped.await;
            })
            .await
    });
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let channel = Endpoint::from_shared(format!("http://{address}"))?
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(3))
            .connect()
            .await?;
        checks(channel, now).await
    })
    .await;
    let _ = stop.send(());
    match tokio::time::timeout(Duration::from_secs(3), &mut server).await {
        Ok(result) => result??,
        Err(_) => {
            server.abort();
            return Err("SERVER_SHUTDOWN_TIMEOUT".into());
        }
    }
    result??;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn real_rpc_conformance() {
        super::run().await.expect("loopback conformance");
    }
    #[test]
    fn bounded_configuration() {
        use super::*;
        for capacity in [0, 65, usize::MAX] {
            assert!(FakeEngine::new(capacity, Arc::new(AtomicU64::new(0))).is_err());
        }
    }
}
