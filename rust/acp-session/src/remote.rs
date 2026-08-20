//! Non-production Remote Profile simulator.
//!
//! The amendment-conformant production authority is the Python `RemoteHost` /
//! `RemoteAuthority`. This engine accepts raw session ID strings and does not
//! consume validated ACP envelopes or authenticated transport principals. It is
//! not safe for live show-control outputs.

use crate::session::{Session, SessionError, SessionState};
use acp_model::{Endpoint, Envelope, Json, Qos};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

const MAX_APPLIED: usize = 1024;

#[derive(Debug, Clone)]
pub struct ControlDef {
    pub control_id: String,
    pub control_type: String,
    pub permission: String,
    pub action: String,
    pub concurrency: String,
    pub failsafe: String,
    pub max_hold_ms: u64,
}

#[derive(Debug, Clone)]
pub struct Hold {
    pub invocation_id: String,
    pub session_id: String,
    pub started_ms: u64,
    pub max_hold_ms: u64,
    pub failsafe: String,
    pub lease_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeResult {
    pub status: String,
    pub code: Option<String>,
    pub active: bool,
    pub go_count: u64,
    pub lease_id: Option<String>,
}

pub struct RemoteAuthority {
    pub show_id: String,
    pub show_revision: u64,
    pub layout_id: String,
    pub layout_revision: u64,
    pub armed: bool,
    pub now_ms: u64,
    pub go_count: u64,
    controls: HashMap<String, ControlDef>,
    permissions: HashMap<String, HashSet<String>>,
    holds: HashMap<String, HashMap<String, Hold>>,
    applied: HashMap<String, (String, InvokeResult)>,
    applied_order: VecDeque<String>,
}

impl RemoteAuthority {
    pub fn new(show_id: &str, layout_id: &str) -> Self {
        let mut controls = HashMap::new();
        controls.insert(
            "cue_go".into(),
            ControlDef {
                control_id: "cue_go".into(),
                control_type: "button".into(),
                permission: "remote.operator".into(),
                action: "cue.go".into(),
                concurrency: "shared".into(),
                failsafe: "release_on_disconnect".into(),
                max_hold_ms: 10_000,
            },
        );
        controls.insert(
            "fog_burst".into(),
            ControlDef {
                control_id: "fog_burst".into(),
                control_type: "momentary".into(),
                permission: "remote.busker".into(),
                action: "busk.fog.output".into(),
                concurrency: "shared".into(),
                failsafe: "release_on_disconnect".into(),
                max_hold_ms: 10_000,
            },
        );
        Self {
            show_id: show_id.into(),
            show_revision: 1,
            layout_id: layout_id.into(),
            layout_revision: 8,
            armed: true,
            now_ms: 0,
            go_count: 0,
            controls,
            permissions: HashMap::new(),
            holds: HashMap::new(),
            applied: HashMap::new(),
            applied_order: VecDeque::new(),
        }
    }

    pub fn authorize(&mut self, identity_id: &str, roles: &[&str]) {
        self.permissions.insert(
            identity_id.into(),
            roles.iter().map(|s| (*s).to_string()).collect(),
        );
        self.reconcile();
    }

    pub fn grant(&mut self, identity_id: &str, roles: &[&str]) {
        self.authorize(identity_id, roles);
    }

    pub fn set_control(&mut self, control: ControlDef) {
        self.controls.insert(control.control_id.clone(), control);
    }

    pub fn effect_active(&self, control_id: &str) -> bool {
        self.holds
            .get(control_id)
            .map(|g| !g.is_empty())
            .unwrap_or(false)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn invoke(
        &mut self,
        session_id: &str,
        control_id: &str,
        invocation_id: &str,
        interaction: &str,
        show_id: Option<&str>,
        layout_id: Option<&str>,
        lease_id: Option<&str>,
    ) -> InvokeResult {
        let applied_key = format!("{session_id}:{invocation_id}:{interaction}");
        let fingerprint = format!(
            "{control_id}|{interaction}|{show:?}|{layout:?}|{lease:?}",
            show = show_id.unwrap_or(""),
            layout = layout_id.unwrap_or(""),
            lease = lease_id.unwrap_or(""),
        );
        if !self.armed {
            return fail("remote.control.not_armed");
        }
        if show_id.is_some_and(|s| s != self.show_id)
            || layout_id.is_some_and(|s| s != self.layout_id)
        {
            return fail("remote.layout.stale");
        }
        let Some(control) = self.controls.get(control_id).cloned() else {
            return fail("remote.control.unknown");
        };
        let allowed = self
            .permissions
            .get(session_id)
            .cloned()
            .unwrap_or_default();
        let needed = action_permission(&control.action);
        if !allowed.contains(&needed) {
            return fail("remote.control.permission_denied");
        }
        if let Some((prev_fp, prev)) = self.applied.get(&applied_key) {
            if prev_fp != &fingerprint {
                return fail("conflict");
            }
            return prev.clone();
        }
        let result = match interaction {
            "activate" if control.action == "cue.go" => {
                self.go_count += 1;
                InvokeResult {
                    status: "applied".into(),
                    code: None,
                    active: true,
                    go_count: self.go_count,
                    lease_id: None,
                }
            }
            "momentary_begin" => self.begin(session_id, &control, invocation_id),
            "momentary_end" | "momentary_cancel" => {
                self.end(session_id, &control, invocation_id, lease_id)
            }
            _ => fail("remote.control.invalid_interaction"),
        };
        if result.status != "rejected" {
            if self.applied.len() >= MAX_APPLIED {
                if let Some(old) = self.applied_order.pop_front() {
                    self.applied.remove(&old);
                }
            }
            self.applied
                .insert(applied_key.clone(), (fingerprint, result.clone()));
            self.applied_order.push_back(applied_key);
        }
        result
    }

    fn begin(
        &mut self,
        session_id: &str,
        control: &ControlDef,
        invocation_id: &str,
    ) -> InvokeResult {
        let group = self.holds.entry(control.control_id.clone()).or_default();
        if group.contains_key(invocation_id) {
            return InvokeResult {
                status: "duplicate".into(),
                code: None,
                active: true,
                go_count: self.go_count,
                lease_id: group.get(invocation_id).map(|h| h.lease_id.clone()),
            };
        }
        if control.concurrency == "exclusive" && !group.is_empty() {
            return fail("remote.control.conflict");
        }
        let lease_id = uuid::Uuid::new_v4().to_string();
        group.insert(
            invocation_id.into(),
            Hold {
                invocation_id: invocation_id.into(),
                session_id: session_id.into(),
                started_ms: self.now_ms,
                max_hold_ms: control.max_hold_ms,
                failsafe: control.failsafe.clone(),
                lease_id: lease_id.clone(),
            },
        );
        InvokeResult {
            status: "applied".into(),
            code: None,
            active: true,
            go_count: self.go_count,
            lease_id: Some(lease_id),
        }
    }

    fn end(
        &mut self,
        session_id: &str,
        control: &ControlDef,
        invocation_id: &str,
        lease_id: Option<&str>,
    ) -> InvokeResult {
        let Some(group) = self.holds.get_mut(&control.control_id) else {
            return InvokeResult {
                status: "duplicate".into(),
                code: None,
                active: false,
                go_count: self.go_count,
                lease_id: None,
            };
        };
        if let Some(hold) = group.get(invocation_id) {
            if hold.session_id != session_id {
                return fail("remote.control.permission_denied");
            }
            if lease_id != Some(hold.lease_id.as_str()) {
                return fail("remote.momentary.unknown_invocation");
            }
        }
        if group.remove(invocation_id).is_none() {
            return InvokeResult {
                status: "duplicate".into(),
                code: None,
                active: !group.is_empty(),
                go_count: self.go_count,
                lease_id: None,
            };
        }
        let active = !group.is_empty();
        if !active {
            self.holds.remove(&control.control_id);
        }
        InvokeResult {
            status: "applied".into(),
            code: None,
            active,
            go_count: self.go_count,
            lease_id: None,
        }
    }

    pub fn on_session_lost(&mut self, session_id: &str) {
        for group in self.holds.values_mut() {
            group.retain(|_, hold| {
                !(hold.session_id == session_id && hold.failsafe == "release_on_disconnect")
            });
        }
        self.holds.retain(|_, g| !g.is_empty());
        self.permissions.remove(session_id);
    }

    pub fn tick(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
        for group in self.holds.values_mut() {
            group.retain(|_, hold| now_ms.saturating_sub(hold.started_ms) < hold.max_hold_ms);
        }
        self.holds.retain(|_, g| !g.is_empty());
    }

    fn reconcile(&mut self) {
        self.holds.retain(|cid, group| {
            let needed = self
                .controls
                .get(cid)
                .map(|c| action_permission(&c.action))
                .unwrap_or_else(|| "remote.admin".into());
            group.retain(|_, hold| {
                self.permissions
                    .get(&hold.session_id)
                    .map(|roles| roles.contains(&needed))
                    .unwrap_or(false)
            });
            !group.is_empty()
        });
    }
}

fn action_permission(action: &str) -> String {
    match action {
        "busk.fog.output" | "busk.blinder" => "remote.busker".into(),
        "bridge.blackout" => "remote.admin".into(),
        "nav.song.select" => "remote.show_navigation".into(),
        _ => "remote.operator".into(),
    }
}

/// Binds the non-production Remote simulator to an authenticated ACP session.
/// Invokes are sent as `remote.control.invoke` on the established session and
/// wait for the registry-declared `command.ack` response.
pub struct RemoteSession {
    session: Arc<Session>,
}

impl RemoteSession {
    pub fn new(session: Arc<Session>) -> Self {
        Self { session }
    }

    pub async fn invoke(
        &self,
        control_id: &str,
        interaction: &str,
        invocation_id: Option<&str>,
    ) -> Result<Envelope, SessionError> {
        if self.session.state().await != SessionState::Established {
            return Err(SessionError::new(
                "remote.session.not_ready",
                "remote requires an established session",
            ));
        }
        let profiles = self.session.negotiated_profiles().await;
        if !profiles
            .iter()
            .any(|p| p == "remote" || p == "aurora.remote.prism.v1")
        {
            return Err(SessionError::new(
                "remote.session.not_ready",
                "remote profile was not negotiated",
            ));
        }
        let id = invocation_id
            .map(str::to_string)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let dest = self.session.peer().await.map(|peer| Endpoint {
            node_id: peer.node_id,
            component_id: None,
        });
        let env = Envelope {
            acp: "1.2".into(),
            message_id: Uuid::new_v4().to_string(),
            message_type: "remote.control.invoke".into(),
            source: Endpoint {
                node_id: self.session.local.node_id.clone(),
                component_id: None,
            },
            destination: dest,
            session_id: None,
            sequence: None,
            timestamp_utc: "2026-08-17T16:42:15.231Z".into(),
            correlation_id: Some(id.clone()),
            causation_id: None,
            qos: Qos::Reliable,
            flags: Default::default(),
            payload: Json::object(vec![
                ("control_id", Json::String(control_id.into())),
                ("invocation_id", Json::String(id.clone())),
                ("interaction", Json::String(interaction.into())),
                ("idempotency_key", Json::String(id)),
            ]),
        };
        self.session.request(env, Duration::from_secs(5)).await
    }
}

fn fail(code: &str) -> InvokeResult {
    InvokeResult {
        status: "rejected".into(),
        code: Some(code.into()),
        active: false,
        go_count: 0,
        lease_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready() -> RemoteAuthority {
        let mut a = RemoteAuthority::new("show", "layout");
        a.grant("s1", &["remote.operator", "remote.busker"]);
        a
    }

    #[test]
    fn go_is_idempotent() {
        let mut a = ready();
        let first = a.invoke(
            "s1",
            "cue_go",
            "inv-1",
            "activate",
            Some("show"),
            Some("layout"),
            None,
        );
        let again = a.invoke(
            "s1",
            "cue_go",
            "inv-1",
            "activate",
            Some("show"),
            Some("layout"),
            None,
        );
        assert_eq!(first.status, "applied");
        assert_eq!(again.go_count, 1);
        assert_eq!(a.go_count, 1);
    }

    #[test]
    fn dirty_disconnect_releases() {
        let mut a = ready();
        a.invoke("s1", "fog_burst", "h1", "momentary_begin", None, None, None);
        assert!(a.effect_active("fog_burst"));
        a.on_session_lost("s1");
        assert!(!a.effect_active("fog_burst"));
    }

    #[test]
    fn shared_or_and_max_hold() {
        let mut a = ready();
        a.grant("s2", &["remote.busker"]);
        let first = a.invoke("s1", "fog_burst", "a", "momentary_begin", None, None, None);
        a.invoke("s2", "fog_burst", "b", "momentary_begin", None, None, None);
        a.invoke(
            "s1",
            "fog_burst",
            "a",
            "momentary_end",
            None,
            None,
            first.lease_id.as_deref(),
        );
        assert!(a.effect_active("fog_burst"));
        a.tick(10_001);
        assert!(!a.effect_active("fog_burst"));
    }

    #[test]
    fn cross_session_end_denied() {
        let mut a = ready();
        a.grant("s2", &["remote.busker"]);
        let begun = a.invoke("s1", "fog_burst", "h1", "momentary_begin", None, None, None);
        let stolen = a.invoke(
            "s2",
            "fog_burst",
            "h1",
            "momentary_end",
            None,
            None,
            begun.lease_id.as_deref(),
        );
        assert_eq!(
            stolen.code.as_deref(),
            Some("remote.control.permission_denied")
        );
        assert!(a.effect_active("fog_burst"));
    }

    #[test]
    fn lease_required_to_end() {
        let mut a = ready();
        let begun = a.invoke("s1", "fog_burst", "h1", "momentary_begin", None, None, None);
        let missing = a.invoke("s1", "fog_burst", "h1", "momentary_end", None, None, None);
        assert_eq!(
            missing.code.as_deref(),
            Some("remote.momentary.unknown_invocation")
        );
        let ended = a.invoke(
            "s1",
            "fog_burst",
            "h1",
            "momentary_end",
            None,
            None,
            begun.lease_id.as_deref(),
        );
        assert_eq!(ended.status, "applied");
        assert!(!a.effect_active("fog_burst"));
    }

    #[test]
    fn stale_layout_and_permission() {
        let mut a = ready();
        let stale = a.invoke(
            "s1",
            "cue_go",
            "x",
            "activate",
            Some("other"),
            Some("layout"),
            None,
        );
        assert_eq!(stale.code.as_deref(), Some("remote.layout.stale"));
        a.grant("s1", &["remote.viewer"]);
        let denied = a.invoke(
            "s1",
            "cue_go",
            "y",
            "activate",
            Some("show"),
            Some("layout"),
            None,
        );
        assert_eq!(
            denied.code.as_deref(),
            Some("remote.control.permission_denied")
        );
    }

    #[test]
    fn idempotency_is_body_aware_and_bounded() {
        let mut a = ready();
        let first = a.invoke(
            "s1",
            "cue_go",
            "inv-1",
            "activate",
            Some("show"),
            Some("layout"),
            None,
        );
        let conflict = a.invoke(
            "s1",
            "cue_go",
            "inv-1",
            "activate",
            Some("show"),
            Some("layout"),
            Some("different-lease"),
        );
        assert_eq!(first.status, "applied");
        assert_eq!(conflict.code.as_deref(), Some("conflict"));
        for i in 0..(MAX_APPLIED + 8) {
            let key = format!("bulk-{i}");
            a.invoke(
                "s1",
                "cue_go",
                &key,
                "activate",
                Some("show"),
                Some("layout"),
                None,
            );
        }
        assert!(a.applied.len() <= MAX_APPLIED);
    }

    #[tokio::test]
    async fn remote_session_requires_established_and_profile() {
        let (ta, _tb) = crate::session::Loopback::pair();
        let session = Arc::new(crate::session::Session::new(
            ta,
            crate::session::identity(crate::Role::Remote, "pad"),
            false,
        ));
        let remote = RemoteSession::new(session);
        let err = remote.invoke("cue_go", "activate", None).await.unwrap_err();
        assert_eq!(err.code, "remote.session.not_ready");
    }

    #[tokio::test]
    async fn remote_session_sends_invoke_on_established_session() {
        use crate::session::{default_caps, identity, Loopback, Session};
        use crate::Role;
        let (ta, tb) = Loopback::pair();
        let mut client = Session::new(ta, identity(Role::Remote, "pad"), false);
        let mut server = Session::new(tb, identity(Role::Conductor, "auth"), true);
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
        assert!(client
            .negotiated_profiles()
            .await
            .iter()
            .any(|p| p == "aurora.remote.prism.v1"));
        let remote = RemoteSession::new(Arc::clone(&client));
        let invoke = Envelope {
            acp: "1.2".into(),
            message_id: Uuid::new_v4().to_string(),
            message_type: "remote.control.invoke".into(),
            source: Endpoint {
                node_id: client.local.node_id.clone(),
                component_id: None,
            },
            destination: client.peer().await.map(|p| Endpoint {
                node_id: p.node_id,
                component_id: None,
            }),
            session_id: None,
            sequence: None,
            timestamp_utc: "2026-08-17T16:42:15.231Z".into(),
            correlation_id: Some("0193f8d8-4c4e-7d8b-a2ab-0000000000d1".into()),
            causation_id: None,
            qos: Qos::Reliable,
            flags: Default::default(),
            payload: Json::object(vec![
                ("control_id", Json::String("cue_go".into())),
                (
                    "invocation_id",
                    Json::String("0193f8d8-4c4e-7d8b-a2ab-0000000000d1".into()),
                ),
                ("interaction", Json::String("activate".into())),
                (
                    "idempotency_key",
                    Json::String("0193f8d8-4c4e-7d8b-a2ab-0000000000d1".into()),
                ),
            ]),
        };
        client.send(invoke).await.expect("send invoke");
        let inbound = server.pump_once().await.expect("recv").expect("msg");
        assert_eq!(inbound.message_type, "remote.control.invoke");
        server
            .send(Envelope {
                acp: "1.2".into(),
                message_id: Uuid::new_v4().to_string(),
                message_type: "command.ack".into(),
                source: Endpoint {
                    node_id: server.local.node_id.clone(),
                    component_id: None,
                },
                destination: Some(Endpoint {
                    node_id: inbound.source.node_id.clone(),
                    component_id: None,
                }),
                session_id: None,
                sequence: None,
                timestamp_utc: "2026-08-17T16:42:15.231Z".into(),
                correlation_id: inbound.correlation_id.clone(),
                causation_id: None,
                qos: Qos::Reliable,
                flags: Default::default(),
                payload: Json::object(vec![("status", Json::String("applied".into()))]),
            })
            .await
            .expect("send ack");
        let ack = client.pump_once().await.expect("client recv").expect("ack");
        assert_eq!(ack.message_type, "command.ack");
        assert_eq!(
            ack.correlation_id.as_deref(),
            Some("0193f8d8-4c4e-7d8b-a2ab-0000000000d1")
        );
        assert_eq!(
            crate::registry::lookup("remote.control.invoke")
                .and_then(|row| row.response_type.clone())
                .as_deref(),
            Some("command.ack")
        );
        let _ = remote;
    }
}
