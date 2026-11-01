use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use codev_capture::Direction;
use codev_proxy::{ConnectContext, DirectTcpConnectHandler, ProxyError, TcpConnectHandler};
use tokio::net::TcpStream;

use crate::{
    MitmDecision, MitmPolicy, PlaintextDirection, PlaintextRecord, PlaintextSink, TlsMitmRelay,
};

pub struct ProxyMitmHandler {
    relay: Arc<TlsMitmRelay>,
    policy: MitmPolicy,
    plaintext_sink: Option<Arc<dyn PlaintextSink>>,
}

impl ProxyMitmHandler {
    pub fn new(relay: Arc<TlsMitmRelay>, policy: MitmPolicy) -> Self {
        Self {
            relay,
            policy,
            plaintext_sink: None,
        }
    }

    pub fn with_plaintext_sink(mut self, sink: Arc<dyn PlaintextSink>) -> Self {
        self.plaintext_sink = Some(sink);
        self
    }
}

impl TcpConnectHandler for ProxyMitmHandler {
    fn handle(
        &self,
        client: TcpStream,
        upstream: TcpStream,
        context: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send>> {
        let host = context.target.host();
        let port = context.target.port();
        match self.policy.decide(&host, port, false) {
            MitmDecision::Tunnel => DirectTcpConnectHandler.handle(client, upstream, context),
            MitmDecision::Reject | MitmDecision::BlockQuic => Box::pin(async move {
                Err(ProxyError::Protocol(
                    "HTTPS interception policy rejected an authorized TCP target".into(),
                ))
            }),
            MitmDecision::Intercept => {
                let relay = Arc::clone(&self.relay);
                let external = self.plaintext_sink.clone();
                Box::pin(async move {
                    let flow_id = format!("socks-tcp-{}", context.flow_id);
                    let sink: Arc<dyn PlaintextSink> =
                        Arc::new(ProxyObservationSink { context, external });
                    relay
                        .intercept_streams(client, upstream, &host, &flow_id, Some(sink))
                        .await
                        .map_err(|error| {
                            ProxyError::Protocol(format!(
                                "allowlisted HTTPS interception failed: {error}"
                            ))
                        })?;
                    Ok(())
                })
            }
        }
    }
}

struct ProxyObservationSink {
    context: ConnectContext,
    external: Option<Arc<dyn PlaintextSink>>,
}

impl PlaintextSink for ProxyObservationSink {
    fn observe(&self, record: PlaintextRecord<'_>) -> io::Result<()> {
        let direction = match record.direction {
            PlaintextDirection::ClientToServer => Direction::ClientToServer,
            PlaintextDirection::ServerToClient => Direction::ServerToClient,
        };
        self.context
            .observe_with_origin(
                direction,
                codev_capture::Transport::Tcp,
                codev_capture::FrameOrigin::HttpsMitm,
                record.payload,
            )
            .map_err(io::Error::other)?;
        if let Some(sink) = self.external.as_ref() {
            sink.observe(record)?;
        }
        Ok(())
    }

    fn close(&self, flow_id: &str) -> io::Result<()> {
        if let Some(sink) = self.external.as_ref() {
            sink.close(flow_id)?;
        }
        Ok(())
    }
}
