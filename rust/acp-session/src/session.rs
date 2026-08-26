use crate::negotiate::{
    intersect_capabilities, intersect_profiles, select_encoding, select_version,
    validate_heartbeat, version_leq,
};
use crate::registry::allowed;
use acp_codec::{decode_cbor, decode_json, encode_cbor, encode_json};
use acp_model::{Capability, Endpoint, Envelope, Json, NodeIdentity, ProtocolRange, Qos, Role};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Closed,
    Connecting,
    HelloSent,
    Established,
    GoodbyeSent,
    Failed,
}

#[derive(Debug)]
pub struct SessionError {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for SessionError {}

impl SessionError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

pub struct Loopback {
    tx: tokio::sync::mpsc::UnboundedSender<(Vec<u8>, bool)>,
    rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<(Vec<u8>, bool)>>,
}

impl Loopback {
    pub fn pair() -> (Arc<Self>, Arc<Self>) {
        let (a_tx, a_rx) = tokio::sync::mpsc::unbounded_channel();
        let (b_tx, b_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Arc::new(Self {
                tx: b_tx,
                rx: Mutex::new(a_rx),
            }),
            Arc::new(Self {
                tx: a_tx,
                rx: Mutex::new(b_rx),
            }),
        )
    }

    pub async fn send(&self, data: Vec<u8>, text: bool) -> Result<(), SessionError> {
        self.tx
            .send((data, text))
            .map_err(|_| SessionError::new("unavailable", "loopback closed"))
    }

    pub async fn recv(&self) -> Result<(Vec<u8>, bool), SessionError> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| SessionError::new("unavailable", "loopback eof"))
    }

    pub async fn close(&self) {
        self.rx.lock().await.close();
    }
}

#[derive(Clone)]
pub enum AnyTransport {
    Loopback(Arc<Loopback>),
    Framed(Arc<FramedTcp>),
}

impl From<Arc<Loopback>> for AnyTransport {
    fn from(value: Arc<Loopback>) -> Self {
        Self::Loopback(value)
    }
}

impl From<Arc<FramedTcp>> for AnyTransport {
    fn from(value: Arc<FramedTcp>) -> Self {
        Self::Framed(value)
    }
}

impl AnyTransport {
    async fn send(&self, data: Vec<u8>, text: bool) -> Result<(), SessionError> {
        match self {
            Self::Loopback(t) => t.send(data, text).await,
            Self::Framed(t) => t.send(data, text).await,
        }
    }

    async fn recv(&self) -> Result<(Vec<u8>, bool), SessionError> {
        match self {
            Self::Loopback(t) => t.recv().await,
            Self::Framed(t) => t.recv().await,
        }
    }

    async fn close(&self) {
        match self {
            Self::Loopback(t) => t.close().await,
            Self::Framed(t) => t.close().await,
        }
    }
}

pub struct FramedTcp {
    stream: Mutex<TcpStream>,
}

impl FramedTcp {
    pub async fn connect(addr: &str) -> Result<Arc<Self>, SessionError> {
        let stream = TcpStream::connect(addr)
            .await
            .map_err(|e| SessionError::new("unavailable", e.to_string()))?;
        let _ = stream.set_nodelay(true);
        Ok(Arc::new(Self {
            stream: Mutex::new(stream),
        }))
    }

    pub fn from_stream(stream: TcpStream) -> Arc<Self> {
        let _ = stream.set_nodelay(true);
        Arc::new(Self {
            stream: Mutex::new(stream),
        })
    }

    pub async fn send(&self, data: Vec<u8>, text: bool) -> Result<(), SessionError> {
        if data.len() > 8 * 1024 * 1024 {
            return Err(SessionError::new("invalid_range", "frame too large"));
        }
        let mut stream = self.stream.lock().await;
        let len = (data.len() as u32).to_be_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|e| SessionError::new("unavailable", e.to_string()))?;
        stream
            .write_all(&[u8::from(text)])
            .await
            .map_err(|e| SessionError::new("unavailable", e.to_string()))?;
        stream
            .write_all(&data)
            .await
            .map_err(|e| SessionError::new("unavailable", e.to_string()))?;
        stream
            .flush()
            .await
            .map_err(|e| SessionError::new("unavailable", e.to_string()))?;
        Ok(())
    }

    pub async fn recv(&self) -> Result<(Vec<u8>, bool), SessionError> {
        let mut stream = self.stream.lock().await;
        let mut header = [0u8; 5];
        stream
            .read_exact(&mut header)
            .await
            .map_err(|e| SessionError::new("unavailable", e.to_string()))?;
        let n = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
        if n > 8 * 1024 * 1024 {
            return Err(SessionError::new("invalid_range", "frame too large"));
        }
        let mut buf = vec![0u8; n];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| SessionError::new("unavailable", e.to_string()))?;
        let text = match header[4] {
            0 => false,
            1 => true,
            _ => {
                return Err(SessionError::new(
                    "malformed_envelope",
                    "reserved frame flags",
                ))
            }
        };
        Ok((buf, text))
    }

    pub async fn close(&self) {
        let mut stream = self.stream.lock().await;
        let _ = stream.shutdown().await;
    }
}

struct Inner {
    state: SessionState,
    session_id: Option<String>,
    session_version: String,
    encoding: String,
    peer: Option<NodeIdentity>,
    negotiated: HashSet<String>,
    negotiated_versions: HashMap<String, String>,
    negotiated_profiles: Vec<String>,
    next_sequence: u64,
    last_rx: Option<u64>,
    gap_count: u32,
    inbox: VecDeque<Envelope>,
}

pub struct Session {
    pub local: NodeIdentity,
    pub is_server: bool,
    pub allow_plaintext: bool,
    pub auth_mode: String,
    pub protocol: ProtocolRange,
    pub encodings: Vec<String>,
    pub profiles: Vec<String>,
    transport: AnyTransport,
    inner: Mutex<Inner>,
}

impl Session {
    pub fn new(transport: impl Into<AnyTransport>, local: NodeIdentity, is_server: bool) -> Self {
        Self {
            local,
            is_server,
            allow_plaintext: false,
            auth_mode: "trusted_lan".into(),
            protocol: ProtocolRange {
                min: "1.0".into(),
                max: "1.2".into(),
            },
            encodings: vec!["cbor".into(), "json".into()],
            profiles: vec!["core".into()],
            transport: transport.into(),
            inner: Mutex::new(Inner {
                state: SessionState::Closed,
                session_id: None,
                session_version: "1.2".into(),
                encoding: "cbor".into(),
                peer: None,
                negotiated: HashSet::new(),
                negotiated_versions: HashMap::new(),
                negotiated_profiles: Vec::new(),
                next_sequence: 0,
                last_rx: None,
                gap_count: 0,
                inbox: VecDeque::new(),
            }),
        }
    }

    pub async fn state(&self) -> SessionState {
        self.inner.lock().await.state
    }

    pub async fn session_id(&self) -> Option<String> {
        self.inner.lock().await.session_id.clone()
    }

    pub async fn peer(&self) -> Option<NodeIdentity> {
        self.inner.lock().await.peer.clone()
    }

    pub async fn encoding(&self) -> String {
        self.inner.lock().await.encoding.clone()
    }

    pub async fn session_version(&self) -> String {
        self.inner.lock().await.session_version.clone()
    }

    pub async fn negotiated_profiles(&self) -> Vec<String> {
        self.inner.lock().await.negotiated_profiles.clone()
    }

    pub async fn negotiated_capabilities(&self) -> HashSet<String> {
        self.inner.lock().await.negotiated.clone()
    }

    pub async fn handshake(&self, capabilities: Vec<Capability>) -> Result<Envelope, SessionError> {
        if self.auth_mode == "trusted_lan" && !self.allow_plaintext {
            return Err(SessionError::new(
                "authentication",
                "trusted_lan requires allow_plaintext",
            ));
        }
        self.inner.lock().await.state = SessionState::Connecting;
        if self.is_server {
            let hello = self.wait_type("session.hello").await?;
            return self.accept_hello(&hello, &capabilities).await;
        }
        let hello = self.build_hello(&capabilities);
        self.transmit(hello, false).await?;
        self.inner.lock().await.state = SessionState::HelloSent;
        let ack = self.wait_type("session.hello_ack").await?;
        self.apply_hello_ack(&ack).await?;
        Ok(ack)
    }

    fn build_hello(&self, capabilities: &[Capability]) -> Envelope {
        Envelope {
            acp: "1.2".into(),
            message_id: Uuid::new_v4().to_string(),
            message_type: "session.hello".into(),
            source: Endpoint {
                node_id: self.local.node_id.clone(),
                component_id: None,
            },
            destination: None,
            session_id: None,
            sequence: None,
            timestamp_utc: "2026-08-17T16:42:15.231Z".into(),
            correlation_id: None,
            causation_id: None,
            qos: Qos::Reliable,
            flags: Default::default(),
            payload: Json::object(vec![
                ("node", node_json(&self.local)),
                (
                    "protocol",
                    Json::object(vec![
                        ("min", Json::String(self.protocol.min.clone())),
                        ("max", Json::String(self.protocol.max.clone())),
                    ]),
                ),
                (
                    "encodings",
                    Json::Array(self.encodings.iter().cloned().map(Json::String).collect()),
                ),
                (
                    "profiles",
                    Json::Array(self.profiles.iter().cloned().map(Json::String).collect()),
                ),
                ("capabilities", caps_json(capabilities)),
                (
                    "auth",
                    Json::object(vec![("mode", Json::String(self.auth_mode.clone()))]),
                ),
            ]),
        }
    }

    async fn accept_hello(
        &self,
        hello: &Envelope,
        capabilities: &[Capability],
    ) -> Result<Envelope, SessionError> {
        let payload = &hello.payload;
        let proto = payload
            .get("protocol")
            .ok_or_else(|| SessionError::new("malformed_envelope", "protocol"))?;
        let range = ProtocolRange {
            min: proto
                .get("min")
                .and_then(Json::as_str)
                .unwrap_or("1.0")
                .into(),
            max: proto
                .get("max")
                .and_then(Json::as_str)
                .unwrap_or("1.2")
                .into(),
        };
        let selected = select_version(&range, &self.protocol)
            .map_err(|e| SessionError::new("unsupported_version", e.0))?;
        let encodings: Vec<String> = match payload.get("encodings") {
            Some(Json::Array(a)) => a
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        let encoding = select_encoding(&encodings, &self.encodings)
            .map_err(|e| SessionError::new("unsupported_version", e.0))?;
        let peer = node_from_json(payload.get("node"))
            .ok_or_else(|| SessionError::new("authentication", "missing node"))?;
        if hello.source.node_id != peer.node_id {
            return Err(SessionError::new("authentication", "HELLO source mismatch"));
        }
        let peer_caps = caps_from_json(payload.get("capabilities"));
        let negotiated = intersect_capabilities(capabilities, &peer_caps);
        let peer_profiles: Vec<String> = match payload.get("profiles") {
            Some(Json::Array(a)) => a
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_string)
                .collect(),
            _ => Vec::new(),
        };
        let negotiated_profiles = intersect_profiles(&self.profiles, &peer_profiles);
        let session_id = Uuid::new_v4().to_string();
        {
            let mut g = self.inner.lock().await;
            g.peer = Some(peer);
            g.negotiated_versions = negotiated
                .iter()
                .map(|c| (c.id.clone(), c.version.clone()))
                .collect();
            g.negotiated = g.negotiated_versions.keys().cloned().collect();
            g.negotiated_profiles = negotiated_profiles.clone();
            g.session_id = Some(session_id.clone());
            g.session_version = selected.clone();
            g.encoding = encoding.clone();
            g.next_sequence = 0;
            g.last_rx = None;
            g.gap_count = 0;
            g.state = SessionState::Established;
        }
        let ack = Envelope {
            acp: "1.2".into(),
            message_id: Uuid::new_v4().to_string(),
            message_type: "session.hello_ack".into(),
            source: Endpoint {
                node_id: self.local.node_id.clone(),
                component_id: None,
            },
            destination: None,
            session_id: None,
            sequence: None,
            timestamp_utc: "2026-08-17T16:42:15.231Z".into(),
            correlation_id: None,
            causation_id: None,
            qos: Qos::Reliable,
            flags: Default::default(),
            payload: Json::object(vec![
                ("accepted", Json::Bool(true)),
                ("protocol", Json::String(selected)),
                ("encoding", Json::String(encoding)),
                ("session_id", Json::String(session_id)),
                ("heartbeat_interval_ms", Json::Int(1000)),
                ("node", node_json(&self.local)),
                ("peer_capabilities", caps_json(&negotiated)),
                (
                    "profiles",
                    Json::Array(negotiated_profiles.into_iter().map(Json::String).collect()),
                ),
                (
                    "limits",
                    Json::object(vec![("max_message_bytes", Json::Int(1_048_576))]),
                ),
            ]),
        };
        self.transmit(ack.clone(), false).await?;
        Ok(ack)
    }

    async fn apply_hello_ack(&self, ack: &Envelope) -> Result<(), SessionError> {
        let payload = &ack.payload;
        if payload.get("accepted").and_then(Json::as_bool) != Some(true) {
            self.inner.lock().await.state = SessionState::Failed;
            return Err(SessionError::new("unsupported_version", "hello rejected"));
        }
        let session_id = payload
            .get("session_id")
            .and_then(Json::as_str)
            .ok_or_else(|| SessionError::new("malformed_envelope", "missing session_id"))?
            .to_string();
        let protocol = payload
            .get("protocol")
            .and_then(Json::as_str)
            .ok_or_else(|| SessionError::new("malformed_envelope", "missing protocol"))?
            .to_string();
        if !version_leq(&self.protocol.min, &protocol)
            || !version_leq(&protocol, &self.protocol.max)
        {
            return Err(SessionError::new(
                "malformed_envelope",
                "protocol outside offer",
            ));
        }
        let encoding = payload
            .get("encoding")
            .and_then(Json::as_str)
            .ok_or_else(|| SessionError::new("malformed_envelope", "missing encoding"))?
            .to_string();
        if !self.encodings.iter().any(|e| e == &encoding) {
            return Err(SessionError::new(
                "malformed_envelope",
                "encoding not offered",
            ));
        }
        let _ = validate_heartbeat(
            payload
                .get("heartbeat_interval_ms")
                .and_then(Json::as_i64)
                .unwrap_or(1000),
        )
        .map_err(|e| SessionError::new("malformed_envelope", e.0))?;
        let peer = node_from_json(payload.get("node"))
            .ok_or_else(|| SessionError::new("authentication", "hello_ack missing node"))?;
        if ack.source.node_id != peer.node_id {
            return Err(SessionError::new("authentication", "ACK source mismatch"));
        }
        let negotiated_caps = caps_from_json(payload.get("peer_capabilities"));
        let ack_profiles: Vec<String> = match payload.get("profiles") {
            Some(Json::Array(a)) => a
                .iter()
                .filter_map(Json::as_str)
                .map(str::to_string)
                .collect(),
            _ => intersect_profiles(&self.profiles, &self.profiles),
        };
        let mut g = self.inner.lock().await;
        g.session_id = Some(session_id);
        g.session_version = protocol;
        g.encoding = encoding;
        g.peer = Some(peer);
        g.negotiated_versions = negotiated_caps
            .iter()
            .map(|c| (c.id.clone(), c.version.clone()))
            .collect();
        g.negotiated = g.negotiated_versions.keys().cloned().collect();
        g.negotiated_profiles = intersect_profiles(&self.profiles, &ack_profiles);
        g.next_sequence = 0;
        g.last_rx = None;
        g.gap_count = 0;
        g.state = SessionState::Established;
        Ok(())
    }

    pub async fn send(&self, env: Envelope) -> Result<Envelope, SessionError> {
        {
            let g = self.inner.lock().await;
            if g.state == SessionState::Established {
                let negotiated: Vec<String> = g.negotiated.iter().cloned().collect();
                if let Some(err) = allowed(
                    &env.message_type,
                    self.local.role.as_str(),
                    &negotiated,
                    true,
                    Some(env.qos.as_str()),
                    Some(&env.acp),
                    Some(&g.negotiated_versions),
                ) {
                    return Err(SessionError::new(
                        err,
                        format!("not allowed to send {}", env.message_type),
                    ));
                }
            }
        }
        let established = self.inner.lock().await.state == SessionState::Established;
        self.transmit(env, established).await
    }

    pub async fn request(
        &self,
        mut env: Envelope,
        timeout: Duration,
    ) -> Result<Envelope, SessionError> {
        if env.correlation_id.is_none() {
            env.correlation_id = Some(env.message_id.clone());
        }
        let corr = env.correlation_id.clone();
        let expected =
            crate::registry::lookup(&env.message_type).and_then(|row| row.response_type.clone());
        self.send(env).await?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            {
                let mut g = self.inner.lock().await;
                if let Some(pos) = g.inbox.iter().position(|item| {
                    item.correlation_id == corr
                        && (expected.as_deref() == Some(item.message_type.as_str())
                            || item.message_type == "error.report")
                }) {
                    return Ok(g.inbox.remove(pos).expect("pos"));
                }
            }
            match tokio::time::timeout_at(deadline, self.pump_once()).await {
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(SessionError::new("timeout", "request timed out"));
                }
            }
        }
    }

    pub async fn goodbye(&self) -> Result<(), SessionError> {
        let established = {
            let mut g = self.inner.lock().await;
            let est = g.state == SessionState::Established;
            g.state = if est {
                SessionState::GoodbyeSent
            } else {
                SessionState::Closed
            };
            est
        };
        if established {
            let env = Envelope {
                acp: "1.2".into(),
                message_id: Uuid::new_v4().to_string(),
                message_type: "session.goodbye".into(),
                source: Endpoint {
                    node_id: self.local.node_id.clone(),
                    component_id: None,
                },
                destination: None,
                session_id: self.session_id().await,
                sequence: None,
                timestamp_utc: "2026-08-17T16:42:15.231Z".into(),
                correlation_id: None,
                causation_id: None,
                qos: Qos::BestEffort,
                flags: Default::default(),
                payload: Json::object(vec![("reason", Json::String("shutdown".into()))]),
            };
            let _ = self.transmit(env, true).await;
        }
        self.inner.lock().await.state = SessionState::Closed;
        self.transport.close().await;
        Ok(())
    }

    async fn transmit(
        &self,
        mut env: Envelope,
        established: bool,
    ) -> Result<Envelope, SessionError> {
        let encoding = {
            let mut g = self.inner.lock().await;
            if established {
                if g.session_id.is_none() {
                    return Err(SessionError::new("internal", "no session"));
                }
                if env.sequence.is_none() {
                    g.next_sequence += 1;
                    env.session_id = g.session_id.clone();
                    env.sequence = Some(g.next_sequence);
                }
            }
            g.encoding.clone()
        };
        let raw = if encoding == "json" {
            encode_json(&env).map_err(|e| SessionError::new("internal", e.0))?
        } else {
            encode_cbor(&env).map_err(|e| SessionError::new("internal", e.0))?
        };
        self.transport.send(raw, encoding == "json").await?;
        Ok(env)
    }

    pub async fn pump_once(&self) -> Result<Option<Envelope>, SessionError> {
        let (raw, text) = match self.transport.recv().await {
            Ok(v) => v,
            Err(e) => {
                self.inner.lock().await.state = SessionState::Failed;
                return Err(e);
            }
        };
        let env = if text {
            decode_json(&raw).map_err(|e| SessionError::new("malformed_envelope", e.0))?
        } else {
            decode_cbor(&raw).map_err(|e| SessionError::new("malformed_envelope", e.0))?
        };
        if let Some(code) = self.admit(&env).await {
            return Err(SessionError::new(
                code,
                format!("inbound rejected {}", env.message_type),
            ));
        }
        let established = self.inner.lock().await.state == SessionState::Established;
        if established {
            self.check_sequence(&env).await?;
        }
        {
            let mut g = self.inner.lock().await;
            if env.message_type == "session.goodbye" {
                g.state = SessionState::Closed;
            }
            g.inbox.push_back(env.clone());
        }
        Ok(Some(env))
    }

    async fn wait_type(&self, typ: &str) -> Result<Envelope, SessionError> {
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
        loop {
            {
                let mut g = self.inner.lock().await;
                if let Some(pos) = g.inbox.iter().position(|e| e.message_type == typ) {
                    return Ok(g.inbox.remove(pos).expect("pos"));
                }
            }
            match tokio::time::timeout_at(deadline, self.pump_once()).await {
                Ok(Ok(Some(env))) if env.message_type == typ => return Ok(env),
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(SessionError::new("timeout", format!("waiting for {typ}")));
                }
            }
        }
    }

    async fn admit(&self, env: &Envelope) -> Option<&'static str> {
        let g = self.inner.lock().await;
        if g.state != SessionState::Established {
            if crate::registry::lookup(&env.message_type).map(|r| r.legal_before_handshake)
                != Some(true)
            {
                return Some("malformed_envelope");
            }
            if self.is_server
                && env.message_type != "session.hello"
                && env.message_type != "error.report"
            {
                return Some("malformed_envelope");
            }
            return None;
        }
        if env.session_id.as_deref() != g.session_id.as_deref() {
            return Some("malformed_envelope");
        }
        if env.sequence.unwrap_or(0) < 1 {
            return Some("malformed_envelope");
        }
        if !version_leq(&env.acp, &g.session_version) {
            return Some("unsupported_version");
        }
        let Some(peer) = &g.peer else {
            return Some("authentication");
        };
        if env.source.node_id != peer.node_id {
            return Some("authentication");
        }
        let negotiated: Vec<String> = g.negotiated.iter().cloned().collect();
        allowed(
            &env.message_type,
            peer.role.as_str(),
            &negotiated,
            true,
            Some(env.qos.as_str()),
            Some(&env.acp),
            Some(&g.negotiated_versions),
        )
    }

    async fn check_sequence(&self, env: &Envelope) -> Result<bool, SessionError> {
        let seq = env.sequence.unwrap_or(0);
        let mut g = self.inner.lock().await;
        match g.last_rx {
            None if seq == 1 => {
                g.last_rx = Some(1);
                Ok(true)
            }
            None if seq > 2 => {
                g.state = SessionState::Failed;
                Err(SessionError::new(
                    "protocol.sequence_gap",
                    "first sequence is not 1",
                ))
            }
            None => {
                g.last_rx = Some(seq);
                g.gap_count += 1;
                Ok(true)
            }
            Some(last) if seq <= last => Ok(false),
            Some(last) if seq == last + 1 => {
                g.last_rx = Some(seq);
                Ok(true)
            }
            Some(_) => {
                g.gap_count += 1;
                g.last_rx = Some(seq);
                if g.gap_count >= 2 {
                    g.state = SessionState::Failed;
                    return Err(SessionError::new(
                        "protocol.sequence_gap",
                        "sequence gap reset",
                    ));
                }
                Ok(true)
            }
        }
    }
}

fn node_json(node: &NodeIdentity) -> Json {
    Json::object(vec![
        ("node_id", Json::String(node.node_id.clone())),
        ("instance_id", Json::String(node.instance_id.clone())),
        ("role", Json::String(node.role.as_str().into())),
        ("name", Json::String(node.name.clone())),
    ])
}

fn caps_json(capabilities: &[Capability]) -> Json {
    Json::Array(
        capabilities
            .iter()
            .map(|c| {
                Json::object(vec![
                    ("id", Json::String(c.id.clone())),
                    ("version", Json::String(c.version.clone())),
                ])
            })
            .collect(),
    )
}

fn node_from_json(value: Option<&Json>) -> Option<NodeIdentity> {
    let v = value?;
    Some(NodeIdentity {
        node_id: v.get("node_id")?.as_str()?.to_string(),
        instance_id: v.get("instance_id")?.as_str()?.to_string(),
        role: Role::parse(v.get("role")?.as_str()?)?,
        name: v.get("name")?.as_str()?.to_string(),
        product_version: v
            .get("product_version")
            .and_then(Json::as_str)
            .map(str::to_string),
    })
}

fn caps_from_json(value: Option<&Json>) -> Vec<Capability> {
    match value {
        Some(Json::Array(items)) => items
            .iter()
            .filter_map(|item| {
                Some(Capability {
                    id: item.get("id")?.as_str()?.to_string(),
                    version: item.get("version")?.as_str()?.to_string(),
                })
            })
            .collect(),
        _ => Vec::new(),
    }
}

pub fn identity(role: Role, name: &str) -> NodeIdentity {
    NodeIdentity {
        node_id: Uuid::new_v4().to_string(),
        instance_id: Uuid::new_v4().to_string(),
        role,
        name: name.into(),
        product_version: Some("1.2.0".into()),
    }
}

pub fn default_caps() -> Vec<Capability> {
    let mut caps: Vec<Capability> = [
        "health.heartbeat",
        "prism.cue_control",
        "bridge.blackout",
        "bridge.config",
        "remote.profile",
        "remote.control.invoke",
        "remote.control.momentary",
    ]
    .into_iter()
    .map(|id| Capability {
        id: id.into(),
        version: "1.0".into(),
    })
    .collect();
    caps.push(Capability {
        id: "resource.transfer".into(),
        version: "1.2".into(),
    });
    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rust_loopback_handshake_and_peer_role() {
        let (ta, tb) = Loopback::pair();
        let mut client = Session::new(ta, identity(Role::Conductor, "c"), false);
        let mut server = Session::new(tb, identity(Role::Bridge, "b"), true);
        client.allow_plaintext = true;
        server.allow_plaintext = true;
        let client = Arc::new(client);
        let server = Arc::new(server);
        let caps = default_caps();
        let server_h = {
            let server = Arc::clone(&server);
            let caps = caps.clone();
            tokio::spawn(async move { server.handshake(caps).await })
        };
        client.handshake(caps).await.unwrap();
        server_h.await.unwrap().unwrap();
        assert_eq!(client.state().await, SessionState::Established);
        assert_eq!(server.state().await, SessionState::Established);
        assert_eq!(client.peer().await.unwrap().role, Role::Bridge);
        assert_eq!(server.peer().await.unwrap().role, Role::Conductor);
        client.goodbye().await.unwrap();
    }

    #[tokio::test]
    async fn assign_sequence_requires_established() {
        let (ta, _tb) = Loopback::pair();
        let s = Session::new(ta, identity(Role::Tool, "t"), false);
        assert_eq!(s.state().await, SessionState::Closed);
        assert!(s.session_id().await.is_none());
    }

    #[tokio::test]
    async fn plaintext_required() {
        let (ta, _tb) = Loopback::pair();
        let s = Session::new(ta, identity(Role::Tool, "t"), false);
        let err = s.handshake(vec![]).await.unwrap_err();
        assert_eq!(err.code, "authentication");
    }

    #[tokio::test]
    async fn negotiates_remote_profiles() {
        let (ta, tb) = Loopback::pair();
        let mut client = Session::new(ta, identity(Role::Remote, "pad"), false);
        let mut server = Session::new(tb, identity(Role::Conductor, "auth"), true);
        client.allow_plaintext = true;
        server.allow_plaintext = true;
        client.profiles = vec![
            "core".into(),
            "remote".into(),
            "aurora.remote.prism.v1".into(),
        ];
        server.profiles = vec![
            "core".into(),
            "remote".into(),
            "aurora.remote.prism.v1".into(),
        ];
        let client = Arc::new(client);
        let server = Arc::new(server);
        let caps = default_caps();
        let server_h = {
            let server = Arc::clone(&server);
            let caps = caps.clone();
            tokio::spawn(async move { server.handshake(caps).await })
        };
        client.handshake(caps).await.unwrap();
        server_h.await.unwrap().unwrap();
        let profiles = client.negotiated_profiles().await;
        assert!(profiles.iter().any(|p| p == "aurora.remote.prism.v1"));
        assert!(client
            .negotiated_capabilities()
            .await
            .contains("remote.profile"));
    }

    fn envelope(
        typ: &str,
        source: &str,
        dest: Option<&str>,
        payload: Json,
        corr: Option<String>,
    ) -> Envelope {
        Envelope {
            acp: "1.2".into(),
            message_id: Uuid::new_v4().to_string(),
            message_type: typ.into(),
            source: Endpoint {
                node_id: source.into(),
                component_id: None,
            },
            destination: dest.map(|node_id| Endpoint {
                node_id: node_id.into(),
                component_id: None,
            }),
            session_id: None,
            sequence: None,
            timestamp_utc: "2026-08-17T16:42:15.231Z".into(),
            correlation_id: corr,
            causation_id: None,
            qos: Qos::Reliable,
            flags: Default::default(),
            payload,
        }
    }

    #[tokio::test]
    async fn request_matches_registry_response() {
        let (ta, tb) = Loopback::pair();
        let mut client = Session::new(ta, identity(Role::Remote, "pad"), false);
        let mut server = Session::new(tb, identity(Role::Conductor, "auth"), true);
        client.allow_plaintext = true;
        server.allow_plaintext = true;
        let client = Arc::new(client);
        let server = Arc::new(server);
        let caps = default_caps();
        let server_h = {
            let server = Arc::clone(&server);
            let caps = caps.clone();
            tokio::spawn(async move { server.handshake(caps).await })
        };
        client.handshake(caps).await.unwrap();
        server_h.await.unwrap().unwrap();
        let dest = client.peer().await.unwrap().node_id;
        let mut req = envelope(
            "state.request",
            &client.local.node_id,
            Some(&dest),
            Json::object(vec![("resources", Json::Array(vec![]))]),
            None,
        );
        req.correlation_id = Some(req.message_id.clone());
        client.send(req.clone()).await.expect("send state.request");
        let inbound = server.pump_once().await.expect("server recv").expect("msg");
        assert_eq!(inbound.message_type, "state.request");
        assert_eq!(
            crate::registry::lookup("state.request")
                .and_then(|row| row.response_type.clone())
                .as_deref(),
            Some("state.snapshot")
        );
        server
            .send(envelope(
                "state.snapshot",
                &server.local.node_id,
                Some(&inbound.source.node_id),
                Json::object(vec![("resources", Json::Array(vec![]))]),
                inbound.correlation_id.clone(),
            ))
            .await
            .expect("send snapshot");
        let ack = client.pump_once().await.expect("client recv").expect("ack");
        assert_eq!(ack.message_type, "state.snapshot");
        assert_eq!(ack.correlation_id, req.correlation_id);
    }
}
