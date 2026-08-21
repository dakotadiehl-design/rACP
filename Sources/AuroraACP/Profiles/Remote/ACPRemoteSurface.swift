import CryptoKit
import Foundation

public enum ACPRemoteSurfaceStatus: Sendable, Equatable {
    case accepted(ACPRemoteLayout, skippedControlIDs: [String])
    case rejected(String)
}

public enum ACPRemoteSurfaceValidator {
    public static let clientSchema = "1.0"

    public static let executableKeys: Set<String> = [
        "script", "javascript", "js", "lua", "python", "wasm", "html", "command", "shell",
        "bytecode", "plugin", "url", "href", "path", "file", "filename", "exec", "eval",
        "src", "onclick", "onpress", "code", "binary", "wasm_b64", "executable", "source",
        "expression",
    ]

    public static let nativeActions: [ACPRemoteAction] = [
        .showSongSelect, .cueGo, .outputGrandMasterSet, .outputBlackoutSet,
    ]

    public static func fingerprint(_ object: [String: AnySendable]) -> String {
        var copy = object
        copy["sha256"] = nil
        let canonical = canonicalJSON(.object(copy))
        let digest = SHA256.hash(data: Data(canonical.utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    public static func evaluate(_ object: [String: AnySendable]) -> ACPRemoteSurfaceStatus {
        if let executable = executableReason(.object(object)) {
            return .rejected(executable)
        }
        guard let layout = ACPRemoteLayout.from(object) else {
            return .rejected("surface is structurally invalid")
        }
        if let declared = layout.sha256, declared != fingerprint(object) {
            return .rejected("hash_mismatch")
        }
        if !schemaCompatible(
            min: layout.minClientSchema ?? "1.0",
            max: layout.maxClientSchema ?? layout.schemaVersion
        ) {
            return .rejected("incompatible surface schema")
        }
        if let profile = layout.compatibleProfile,
           profile != ACPRemoteProfileID.prismV1.rawValue,
           profile != ACPRemoteProfileID.legacy.rawValue {
            return .rejected("incompatible surface schema")
        }
        let ids = layout.controls.map(\.controlID)
        if Set(ids).count != ids.count {
            return .rejected("duplicate control_id")
        }
        var skipped: [String] = []
        for control in layout.controls {
            if let min = control.min, let max = control.max, min > max {
                return .rejected("min greater than max")
            }
            if control.safety.failsafeRequired && (control.safety.maxHoldMs == 0 || control.safety.failsafe == "hold_last_state") {
                return .rejected("failsafe-required control cannot be leased")
            }
            if !ACPRemoteAction(rawValue: control.binding.action).isAllowlisted {
                return .rejected("action is not allowlisted")
            }
            let target = control.binding.target
            if !target.isEmpty && !["prism", "conductor", "bridge"].contains(target) {
                return .rejected("unknown binding target")
            }
            if looksLikeImplementationBinding(control.binding) {
                return .rejected("binding is not semantic")
            }
            if !ACPRemoteControlType(rawValue: control.controlType).isKnown {
                skipped.append(control.controlID)
            }
        }
        return .accepted(layout, skippedControlIDs: skipped)
    }

    public static func isInvocable(_ control: ACPRemoteControl) -> Bool {
        ACPRemoteControlType(rawValue: control.controlType).isKnown
            && ACPRemoteAction(rawValue: control.action).isAllowlisted
    }

    private static func schemaCompatible(min: String, max: String) -> Bool {
        ACPNegotiate.versionAtLeast(clientSchema, min) && ACPNegotiate.versionLeq(clientSchema, max)
    }

    private static func looksLikeImplementationBinding(_ binding: ACPRemoteBinding) -> Bool {
        let blob = (binding.target + " " + binding.action).lowercased()
        if blob.contains("dmx") || blob.contains("selector") || blob.contains("::") { return true }
        if binding.action.contains("/") || binding.action.contains(" ") { return true }
        return false
    }

    private static func executableReason(_ value: AnySendable, key: String = "", depth: Int = 0) -> String? {
        if depth > 16 { return "surface nesting too deep" }
        let norm = key.lowercased().replacingOccurrences(of: "-", with: "_")
        if executableKeys.contains(norm) || norm.hasPrefix("on_") {
            return "executable surface payload"
        }
        switch value {
        case .string(let text) where text.contains("://"):
            return "executable surface payload"
        case .object(let obj):
            for (nestedKey, nested) in obj {
                if let reason = executableReason(nested, key: nestedKey, depth: depth + 1) {
                    return reason
                }
            }
        case .array(let items):
            for item in items {
                if let reason = executableReason(item, key: "", depth: depth + 1) {
                    return reason
                }
            }
        default:
            break
        }
        return nil
    }

    private static func canonicalJSON(_ value: AnySendable) -> String {
        switch value {
        case .null: return "null"
        case .bool(let flag): return flag ? "true" : "false"
        case .int(let number): return String(number)
        case .uint(let number): return String(number)
        case .double(let number):
            if number.rounded() == number, let asInt = Int64(exactly: number) {
                return String(asInt) + ".0"
            }
            return String(number)
        case .string(let text):
            return "\"" + escape(text) + "\""
        case .bytes(let data):
            return "\"" + data.base64EncodedString() + "\""
        case .array(let items):
            return "[" + items.map(canonicalJSON).joined(separator: ",") + "]"
        case .object(let obj):
            let keys = obj.keys.sorted()
            let parts = keys.map { key in
                "\"" + escape(key) + "\":" + canonicalJSON(obj[key] ?? .null)
            }
            return "{" + parts.joined(separator: ",") + "}"
        }
    }

    private static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }
}
