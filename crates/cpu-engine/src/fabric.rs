use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, header, http::HeaderMap};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls::pki_types::ServerName};

pub(crate) type Result<T> = std::result::Result<T, &'static str>;
pub(crate) const CONTROL: usize = 65536;

pub(crate) struct Reply {
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[tonic::async_trait]
pub(crate) trait Fabric: Send + Sync + 'static {
    async fn call(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Bytes,
        status: u16,
        limit: usize,
    ) -> Result<Reply>;
}

pub(crate) struct Client {
    pub address: std::net::SocketAddr,
    pub tls: Arc<tokio_rustls::rustls::ClientConfig>,
}

struct ConnectionDriver(tokio::task::AbortHandle);

impl Drop for ConnectionDriver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tonic::async_trait]
impl Fabric for Client {
    async fn call(
        &self,
        method: &str,
        path: &str,
        token: &str,
        body: Bytes,
        status: u16,
        limit: usize,
    ) -> Result<Reply> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let failed = |_| "UNAVAILABLE";
            let stream = TcpStream::connect(self.address).await.map_err(failed)?;
            let stream = TlsConnector::from(self.tls.clone())
                .connect(ServerName::IpAddress(self.address.ip().into()), stream)
                .await
                .map_err(failed)?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(|_| "UNAVAILABLE")?;
            let _driver = ConnectionDriver(tokio::spawn(connection).abort_handle());
            let mut credential = header::HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| "INTERNAL")?;
            credential.set_sensitive(true);
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header(header::HOST, self.address.to_string())
                .header(header::CONNECTION, "close")
                .header(
                    header::CONTENT_TYPE,
                    if method == "PUT" {
                        "application/octet-stream"
                    } else {
                        "application/json"
                    },
                )
                .header(header::AUTHORIZATION, credential)
                .body(Full::new(body))
                .map_err(|_| "INTERNAL")?;
            let response = sender
                .send_request(request)
                .await
                .map_err(|_| "UNAVAILABLE")?;
            let (head, body) = response.into_parts();
            let success = head.status.as_u16() == status;
            let body = Limited::new(body, if success { limit } else { CONTROL })
                .collect()
                .await
                .map_err(|_| "UNAVAILABLE")?
                .to_bytes();
            if !success {
                let error = serde_json::from_slice::<serde_json::Value>(&body).ok();
                return Err(
                    match error.as_ref().and_then(|value| value["code"].as_str()) {
                        Some("ATTEMPT_EXPIRED") => "DEADLINE_EXCEEDED",
                        Some("STALE_FENCE") => "CANCELLED",
                        Some("FORBIDDEN" | "INVALID_REQUEST") => "INVALID_REQUEST",
                        Some("QUOTA_EXCEEDED") => "RESOURCE_EXHAUSTED",
                        _ => "UNAVAILABLE",
                    },
                );
            }
            Ok(Reply {
                headers: head.headers,
                body,
            })
        })
        .await
        .map_err(|_| "UNAVAILABLE")?
    }
}
