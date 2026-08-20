//! Framed-TCP session peer for cross-language interop tests.
//!
//! Usage: framed_hello <client|server> <host> <port> [--json] [--remote] [--session] [--xfer]

use acp_model::{Endpoint, Envelope, Json, Qos};
use acp_session::{default_caps, identity, FramedTcp, Role, Session};
use std::env;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "usage: framed_hello <client|server> <host> <port> [--json] [--remote] [--session] [--xfer]"
        );
        std::process::exit(2);
    }
    let mode = args[1].as_str();
    let host = args[2].as_str();
    let port: u16 = args[3].parse().expect("port");
    let json = args.iter().any(|a| a == "--json");
    let remote = args.iter().any(|a| a == "--remote");
    let session_suite = args.iter().any(|a| a == "--session");
    let xfer = args.iter().any(|a| a == "--xfer");
    match mode {
        "client" => run_client(host, port, json, remote, session_suite, xfer).await,
        "server" => run_server(host, port, json, remote, session_suite, xfer).await,
        _ => {
            eprintln!("mode must be client or server");
            std::process::exit(2);
        }
    }
}

fn configure(session: &mut Session, json: bool, remote: bool) {
    if json {
        session.encodings = vec!["json".into()];
    }
    if remote {
        session.profiles = vec![
            "core".into(),
            "remote".into(),
            "aurora.remote.prism.v1".into(),
        ];
    }
}

fn env(
    typ: &str,
    source: &str,
    dest: Option<&str>,
    payload: Json,
    corr: Option<String>,
    qos: Qos,
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
        qos,
        flags: Default::default(),
        payload,
    }
}

async fn serve_established(session: &Session) {
    loop {
        match session.pump_once().await {
            Ok(Some(inbound)) => match inbound.message_type.as_str() {
                "session.goodbye" => break,
                "state.request" => {
                    let reply = env(
                        "state.snapshot",
                        &session.local.node_id,
                        Some(&inbound.source.node_id),
                        Json::object(vec![("resources", Json::Array(vec![]))]),
                        inbound.correlation_id.clone(),
                        Qos::Reliable,
                    );
                    let _ = session.send(reply).await;
                }
                "resource.offer" => {
                    let tid = inbound
                        .payload
                        .get("transfer_id")
                        .and_then(Json::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let reply = env(
                        "resource.accept",
                        &session.local.node_id,
                        Some(&inbound.source.node_id),
                        Json::object(vec![
                            ("transfer_id", Json::String(tid)),
                            ("max_chunk_bytes", Json::UInt(1024)),
                        ]),
                        inbound.correlation_id.clone(),
                        Qos::Reliable,
                    );
                    let _ = session.send(reply).await;
                }
                "resource.complete" => {
                    let tid = inbound
                        .payload
                        .get("transfer_id")
                        .and_then(Json::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let reply = env(
                        "resource.transfer_result",
                        &session.local.node_id,
                        Some(&inbound.source.node_id),
                        Json::object(vec![
                            ("transfer_id", Json::String(tid)),
                            ("status", Json::String("verified".into())),
                        ]),
                        inbound.correlation_id.clone(),
                        Qos::Reliable,
                    );
                    let _ = session.send(reply).await;
                }
                "resource.activate" => {
                    let tid = inbound
                        .payload
                        .get("transfer_id")
                        .and_then(Json::as_str)
                        .unwrap_or_default()
                        .to_string();
                    let reply = env(
                        "resource.activation_result",
                        &session.local.node_id,
                        Some(&inbound.source.node_id),
                        Json::object(vec![
                            ("transfer_id", Json::String(tid)),
                            ("status", Json::String("applied".into())),
                        ]),
                        inbound.correlation_id.clone(),
                        Qos::Reliable,
                    );
                    let _ = session.send(reply).await;
                }
                "remote.control.invoke" => {
                    let reply = env(
                        "command.ack",
                        &session.local.node_id,
                        Some(&inbound.source.node_id),
                        Json::object(vec![("status", Json::String("applied".into()))]),
                        inbound.correlation_id.clone(),
                        Qos::Reliable,
                    );
                    let _ = session.send(reply).await;
                }
                _ => {}
            },
            Ok(None) => continue,
            Err(_) => break,
        }
    }
}

async fn run_session_client(session: &Session, xfer: bool) {
    let dest = session.peer().await.unwrap().node_id;
    let src = session.local.node_id.clone();
    session
        .send(env(
            "health.heartbeat",
            &src,
            None,
            Json::object(vec![
                ("uptime_ms", Json::UInt(1)),
                ("status", Json::String("ok".into())),
            ]),
            None,
            Qos::Latest,
        ))
        .await
        .expect("heartbeat");
    let snap = session
        .request(
            env(
                "state.request",
                &src,
                Some(&dest),
                Json::object(vec![("resources", Json::Array(vec![]))]),
                None,
                Qos::Reliable,
            ),
            Duration::from_secs(5),
        )
        .await
        .expect("state");
    assert_eq!(snap.message_type, "state.snapshot");
    if xfer {
        let tid = "0193f8d8-4c4e-7d8b-a2ab-000000000070";
        let aid = "0193f8d8-4c4e-7d8b-a2ab-000000000071";
        let sha = "a".repeat(64);
        let accept = session
            .request(
                env(
                    "resource.offer",
                    &src,
                    Some(&dest),
                    Json::object(vec![
                        ("transfer_id", Json::String(tid.into())),
                        (
                            "asset",
                            Json::object(vec![
                                ("asset_id", Json::String(aid.into())),
                                ("asset_type", Json::String("lyric.chart".into())),
                                ("revision", Json::UInt(1)),
                                ("sha256", Json::String(sha)),
                                ("size_bytes", Json::UInt(4)),
                            ]),
                        ),
                        (
                            "locator",
                            Json::object(vec![("mode", Json::String("chunked".into()))]),
                        ),
                    ]),
                    None,
                    Qos::Reliable,
                ),
                Duration::from_secs(5),
            )
            .await
            .expect("accept");
        assert_eq!(accept.message_type, "resource.accept");
        session
            .send(env(
                "resource.chunk",
                &src,
                Some(&dest),
                Json::object(vec![
                    ("transfer_id", Json::String(tid.into())),
                    ("offset", Json::UInt(0)),
                    ("length", Json::UInt(4)),
                    ("data", Json::Bytes(vec![0x00, 0x01, 0xff, 0xe0])),
                ]),
                None,
                Qos::Reliable,
            ))
            .await
            .expect("chunk");
        let done = session
            .request(
                env(
                    "resource.complete",
                    &src,
                    Some(&dest),
                    Json::object(vec![("transfer_id", Json::String(tid.into()))]),
                    None,
                    Qos::Reliable,
                ),
                Duration::from_secs(5),
            )
            .await
            .expect("complete");
        assert_eq!(done.message_type, "resource.transfer_result");
        let act = session
            .request(
                env(
                    "resource.activate",
                    &src,
                    Some(&dest),
                    Json::object(vec![
                        ("transfer_id", Json::String(tid.into())),
                        ("idempotency_key", Json::String(tid.into())),
                    ]),
                    None,
                    Qos::Reliable,
                ),
                Duration::from_secs(5),
            )
            .await
            .expect("activate");
        assert_eq!(act.message_type, "resource.activation_result");
        let ack = session
            .request(
                env(
                    "remote.control.invoke",
                    &src,
                    Some(&dest),
                    Json::object(vec![
                        ("control_id", Json::String("cue_go".into())),
                        ("invocation_id", Json::String(tid.into())),
                        ("interaction", Json::String("activate".into())),
                        ("idempotency_key", Json::String(tid.into())),
                    ]),
                    None,
                    Qos::Reliable,
                ),
                Duration::from_secs(5),
            )
            .await
            .expect("invoke");
        assert_eq!(ack.message_type, "command.ack");
    }
}

async fn run_client(
    host: &str,
    port: u16,
    json: bool,
    remote: bool,
    session_suite: bool,
    xfer: bool,
) {
    let transport = FramedTcp::connect(&format!("{host}:{port}"))
        .await
        .expect("connect");
    let role = if remote {
        Role::Remote
    } else {
        Role::Conductor
    };
    let mut session = Session::new(transport, identity(role, "rs-client"), false);
    configure(&mut session, json, remote);
    let session = Arc::new(session);
    session.handshake(default_caps()).await.expect("handshake");
    println!(
        "ok client {} {} {}",
        session.session_id().await.unwrap_or_default(),
        session.session_version().await,
        session.encoding().await
    );
    if session_suite || xfer {
        run_session_client(&session, xfer).await;
    }
    session.goodbye().await.expect("goodbye");
}

async fn run_server(
    host: &str,
    port: u16,
    json: bool,
    remote: bool,
    session_suite: bool,
    xfer: bool,
) {
    let listener = TcpListener::bind(format!("{host}:{port}"))
        .await
        .expect("bind");
    println!("listening {}", listener.local_addr().unwrap());
    let (stream, _) = listener.accept().await.expect("accept");
    let transport = FramedTcp::from_stream(stream);
    let role = if remote {
        Role::Conductor
    } else {
        Role::Bridge
    };
    let mut session = Session::new(transport, identity(role, "rs-server"), true);
    configure(&mut session, json, remote);
    session.handshake(default_caps()).await.expect("handshake");
    println!(
        "ok server {} {} {}",
        session.session_id().await.unwrap_or_default(),
        session.session_version().await,
        session.encoding().await
    );
    if session_suite || xfer {
        serve_established(&session).await;
    } else {
        session.goodbye().await.expect("goodbye");
    }
}
