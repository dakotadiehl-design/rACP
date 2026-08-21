//! ACP typed models. No Tokio.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Conductor,
    Prism,
    Lyric,
    Bridge,
    Tool,
    Simulator,
    Remote,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Conductor => "conductor",
            Role::Prism => "prism",
            Role::Lyric => "lyric",
            Role::Bridge => "bridge",
            Role::Tool => "tool",
            Role::Simulator => "simulator",
            Role::Remote => "remote",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "conductor" => Some(Self::Conductor),
            "prism" => Some(Self::Prism),
            "lyric" => Some(Self::Lyric),
            "bridge" => Some(Self::Bridge),
            "tool" => Some(Self::Tool),
            "simulator" => Some(Self::Simulator),
            "remote" => Some(Self::Remote),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    pub node_id: String,
    pub instance_id: String,
    pub role: Role,
    pub name: String,
    pub product_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolRange {
    pub min: String,
    pub max: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub node_id: String,
    pub component_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qos {
    Reliable,
    Latest,
    BestEffort,
}

impl Qos {
    pub fn as_str(self) -> &'static str {
        match self {
            Qos::Reliable => "reliable",
            Qos::Latest => "latest",
            Qos::BestEffort => "best_effort",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "reliable" => Some(Self::Reliable),
            "latest" => Some(Self::Latest),
            "best_effort" => Some(Self::BestEffort),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    pub acp: String,
    pub message_id: String,
    pub message_type: String,
    pub source: Endpoint,
    pub destination: Option<Endpoint>,
    pub session_id: Option<String>,
    pub sequence: Option<u64>,
    pub timestamp_utc: String,
    pub correlation_id: Option<String>,
    pub causation_id: Option<String>,
    pub qos: Qos,
    pub flags: BTreeSet<String>,
    pub payload: Json,
}

/// Minimal JSON-like value used on the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn object(pairs: Vec<(&str, Json)>) -> Self {
        Json::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(i) => Some(*i),
            Json::UInt(u) if *u <= i64::MAX as u64 => Some(*u as i64),
            _ => None,
        }
    }
}

pub const PROTOCOL_VERSION: &str = "1.2";

/// Shared Remote-profile identifiers. Rust does not ship a production Remote client;
/// these constants keep the wire vocabulary in parity with Python and Swift.
pub mod remote {
    pub const MAX_LIVE_EPHEMERAL_AGE_MS: u64 = 5_000;

    pub const PROFILE_PRISM: &str = "aurora.remote.prism.v1";
    pub const PROFILE_CONDUCTOR: &str = "aurora.remote.conductor.v1";
    pub const PROFILE_LEGACY: &str = "remote";

    pub const PERMISSIONS: &[&str] = &[
        "observe",
        "song.select",
        "song.load",
        "cue.execute",
        "look.execute",
        "busk.execute",
        "output.grand_master",
        "output.blackout",
        "output.blackout.engage",
        "output.blackout.clear",
        "remote.surface.use",
    ];

    pub const CONTROL_TYPES: &[&str] = &[
        "button",
        "momentary",
        "momentary_button",
        "toggle",
        "slider",
        "fader",
        "encoder",
        "rotary",
        "selector",
        "segmented_selector",
        "xy",
        "xy_pad",
        "transport",
        "navigation",
        "status",
        "meter",
        "color",
        "color_control",
        "preset_tile",
        "label",
        "value_display",
        "status_indicator",
        "group",
        "spacer",
    ];

    pub const ACTIONS: &[&str] = &[
        "cue.go",
        "nav.go",
        "busk.fog.output",
        "busk.work_lights",
        "busk.blinder",
        "bridge.blackout",
        "output.blackout.set",
        "output.grand_master.set",
        "transport.play",
        "transport.stop",
        "nav.song.select",
        "nav.section.enter",
        "show.song.select",
        "show.song.load",
        "show.song.stop",
        "show.song.next",
        "show.song.previous",
        "show.section.next",
        "show.section.previous",
        "show.section.restart",
        "show.progression.hold",
        "show.free_play.enter",
        "show.free_play.exit",
        "look.recall",
        "look.preview",
        "look.take",
        "look.preview.cancel",
        "effects.stop",
    ];

    pub fn is_known_action(action: &str) -> bool {
        ACTIONS.contains(&action)
    }

    pub fn is_known_permission(permission: &str) -> bool {
        PERMISSIONS.contains(&permission)
    }

    pub const CAPABILITIES: &[&str] = &[
        "remote.profile",
        "remote.layout",
        "remote.control.invoke",
        "remote.control.momentary",
        "remote.control.state",
        "remote.navigation.song",
        "remote.navigation.section",
        "remote.navigation.cue",
        "remote.transport",
        "remote.busking",
        "remote.readiness",
        "remote.asset_sync",
        "remote.presentation",
    ];

    pub const EXECUTABLE_SURFACE_KEYS: &[&str] = &[
        "script",
        "javascript",
        "js",
        "lua",
        "python",
        "wasm",
        "html",
        "command",
        "shell",
        "bytecode",
        "plugin",
        "url",
        "href",
        "path",
        "file",
        "filename",
        "exec",
        "eval",
        "src",
        "onclick",
        "onpress",
        "code",
        "binary",
        "wasm_b64",
        "executable",
        "source",
        "expression",
    ];

    pub const STATE_NAMESPACES: &[&str] = &[
        "show.setlist",
        "show.selected_song",
        "show.current_song",
        "show.current_section",
        "show.next_section",
        "show.mode",
        "show.running",
        "show.progression",
        "look.catalog",
        "look.current",
        "look.preview",
        "output.grand_master",
        "output.blackout",
        "system.health",
    ];

    pub const NEVER_COALESCE_ACTIONS: &[&str] = &[
        "performance.go",
        "performance.back",
        "cue.fire",
        "cue.go",
        "momentary.begin",
        "momentary.end",
        "blackoutOn",
        "blackoutOff",
        "nav.go",
        "look.take",
        "show.section.next",
        "show.section.previous",
        "show.section.restart",
        "busk.fog.output",
        "busk.blinder",
    ];

    pub fn action_delivery(action: &str) -> &'static str {
        match action {
            "cue.go" | "nav.go" | "look.take" | "show.section.next" | "show.section.previous"
            | "show.section.restart" | "busk.fog.output" | "busk.blinder" => "live_ephemeral",
            "show.song.select" | "output.blackout.set" | "output.grand_master.set"
            | "busk.work_lights" | "show.progression.hold" | "bridge.blackout"
            | "nav.song.select" => "stateful",
            _ => "impulse",
        }
    }

    pub fn reject_executable(value: &crate::Json) -> Result<(), &'static str> {
        reject_executable_inner(value, "", 0)
    }

    fn reject_executable_inner(
        value: &crate::Json,
        key: &str,
        depth: usize,
    ) -> Result<(), &'static str> {
        if depth > 16 {
            return Err("surface nesting too deep");
        }
        let norm = key.to_ascii_lowercase().replace('-', "_");
        if EXECUTABLE_SURFACE_KEYS.contains(&norm.as_str()) || norm.starts_with("on_") {
            return Err("executable surface payload");
        }
        match value {
            crate::Json::String(text) if text.contains("://") => Err("executable surface payload"),
            crate::Json::Object(pairs) => {
                for (nested_key, nested) in pairs {
                    reject_executable_inner(nested, nested_key, depth + 1)?;
                }
                Ok(())
            }
            crate::Json::Array(items) => {
                for item in items {
                    reject_executable_inner(item, "", depth + 1)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub const FEATURE_CAPABILITIES: &[&str] = &[
        "show.navigation",
        "song.selection",
        "song.loading",
        "cue.go",
        "cue.selection",
        "look.global",
        "remote.surfaces",
        "busk.controls",
        "control.momentary",
        "output.blackout",
        "output.blackout.engage",
        "output.blackout.clear",
        "output.grand_master",
        "state.live",
        "system.health",
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_version_is_baseline() {
        assert_eq!(PROTOCOL_VERSION, "1.2");
    }

    #[test]
    fn remote_prism_1_0_vocabulary_matches_constants() {
        assert_eq!(remote::PROFILE_PRISM, "aurora.remote.prism.v1");
        assert_eq!(remote::PROFILE_CONDUCTOR, "aurora.remote.conductor.v1");
        assert!(remote::is_known_action("show.song.stop"));
        assert!(remote::is_known_action("show.section.next"));
        assert!(remote::is_known_action("effects.stop"));
        assert!(remote::is_known_permission("cue.execute"));
        assert!(remote::CONTROL_TYPES.contains(&"slider"));
        assert!(!remote::is_known_action("prism.internal.setChannel"));
        assert!(remote::CAPABILITIES.contains(&"remote.profile"));
        assert!(remote::FEATURE_CAPABILITIES.contains(&"output.grand_master"));
        assert!(remote::EXECUTABLE_SURFACE_KEYS.contains(&"script"));
        assert!(remote::EXECUTABLE_SURFACE_KEYS.contains(&"expression"));
        assert!(remote::STATE_NAMESPACES.contains(&"show.current_section"));
        assert_eq!(remote::action_delivery("cue.go"), "live_ephemeral");
        assert_eq!(remote::action_delivery("output.grand_master.set"), "stateful");
        assert!(remote::NEVER_COALESCE_ACTIONS.contains(&"nav.go"));
        let bad = Json::object(vec![("expression", Json::String("x+1".into()))]);
        assert!(remote::reject_executable(&bad).is_err());
        let ok = Json::object(vec![("label", Json::String("GO".into()))]);
        assert!(remote::reject_executable(&ok).is_ok());
    }
}
