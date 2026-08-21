import Foundation

enum ACPSchema {
    private static let pack: [String: Any] = {
        let urls = [
            Bundle.module.url(forResource: "schema_pack", withExtension: "json"),
            Bundle.module.url(forResource: "schema_pack", withExtension: "json", subdirectory: "Codec"),
            URL(fileURLWithPath: #filePath)
                .deletingLastPathComponent()
                .appendingPathComponent("schema_pack.json"),
        ]
        for url in urls.compactMap({ $0 }) {
            if let data = try? Data(contentsOf: url),
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return obj
            }
        }
        return [:]
    }()

    private static var docs: [String: Any] {
        pack["docs"] as? [String: Any] ?? [:]
    }

    private static var messages: [String: String] {
        pack["messages"] as? [String: String] ?? [:]
    }

    static func validateEnvelopeObject(_ data: [String: Any]) throws {
        guard let envelope = docs["envelope.schema.json"] as? [String: Any] else {
            throw ACPCodecError.malformed("missing envelope schema")
        }
        do {
            try validate(instance: data, schema: envelope, path: "envelope.schema.json", doc: envelope)
        } catch {
            throw ACPCodecError.malformed("malformed_envelope: \(error)")
        }
        guard let typ = data["type"] as? String else {
            throw ACPCodecError.malformed("malformed_envelope: missing type")
        }
        guard let schemaRef = messages[typ] else {
            throw ACPCodecError.malformed("unsupported_message: unknown type \(typ)")
        }
        let resolved = try resolve(schemaRef, currentPath: "", currentDoc: envelope)
        do {
            try validate(instance: data["payload"] ?? NSNull(), schema: resolved.schema, path: resolved.path, doc: resolved.doc)
        } catch {
            throw ACPCodecError.malformed("invalid_type: \(error)")
        }
    }

    private struct Resolved {
        var schema: [String: Any]
        var path: String
        var doc: [String: Any]
    }

    private static func resolve(_ refer: String, currentPath: String, currentDoc: [String: Any]) throws -> Resolved {
        let parts = refer.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)
        let target = String(parts[0])
        let frag = parts.count > 1 ? String(parts[1]) : ""
        if target.isEmpty {
            return Resolved(schema: try pointer(currentDoc, frag), path: currentPath, doc: currentDoc)
        }
        let joined = joinPath(currentPath, target)
        guard let doc = docs[joined] as? [String: Any] else {
            throw ACPCodecError.malformed("schema \(joined) not packed")
        }
        return Resolved(schema: try pointer(doc, frag), path: joined, doc: doc)
    }

    private static func pointer(_ doc: [String: Any], _ pointer: String) throws -> [String: Any] {
        if pointer.isEmpty { return doc }
        var node: Any = doc
        for part in pointer.split(separator: "/").map(String.init) where !part.isEmpty {
            let key = part.replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~")
            guard let obj = node as? [String: Any], let next = obj[key] else {
                throw ACPCodecError.malformed("schema pointer missing \(key)")
            }
            node = next
        }
        guard let obj = node as? [String: Any] else {
            throw ACPCodecError.malformed("schema pointer not object")
        }
        return obj
    }

    private static func joinPath(_ current: String, _ rel: String) -> String {
        if !rel.contains("/"), !rel.hasPrefix(".") {
            if let slash = current.lastIndex(of: "/") {
                return String(current[..<slash]) + "/" + rel
            }
            return rel
        }
        var parts = Array(current.split(separator: "/").dropLast()).map(String.init)
        for part in rel.split(separator: "/") {
            switch part {
            case ".", "": break
            case "..": _ = parts.popLast()
            default: parts.append(String(part))
            }
        }
        return parts.joined(separator: "/")
    }

    private static func validate(instance: Any, schema: [String: Any], path: String, doc: [String: Any]) throws {
        if let refer = schema["$ref"] as? String {
            let resolved = try resolve(refer, currentPath: path, currentDoc: doc)
            try validate(instance: instance, schema: resolved.schema, path: resolved.path, doc: resolved.doc)
            return
        }
        if let wanted = schema["type"] {
            let got = jsonType(instance)
            let ok: Bool
            if let s = wanted as? String {
                ok = typeOk(got, s)
            } else if let arr = wanted as? [String] {
                ok = arr.contains(where: { typeOk(got, $0) })
            } else {
                ok = true
            }
            if !ok { throw ACPCodecError.malformed("expected \(wanted), got \(got)") }
        }
        if let req = schema["required"] as? [String], let obj = instance as? [String: Any] {
            for key in req where obj[key] == nil {
                throw ACPCodecError.malformed("missing required \(key)")
            }
        }
        if let opts = schema["enum"] as? [Any] {
            if !opts.contains(where: { jsonEqual($0, instance) }) {
                throw ACPCodecError.malformed("value not in enum")
            }
        }
        if let expected = schema["const"] {
            if !jsonEqual(expected, instance) {
                throw ACPCodecError.malformed("const mismatch")
            }
        }
        if let pat = schema["pattern"] as? String, let text = instance as? String {
            if (try? NSRegularExpression(pattern: pat))?.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)) == nil {
                throw ACPCodecError.malformed("pattern \(pat) failed")
            }
        }
        if let min = schema["minLength"] as? Int, let text = instance as? String, text.count < min {
            throw ACPCodecError.malformed("minLength")
        }
        if let min = number(schema["minimum"]), let n = number(instance), n < min {
            throw ACPCodecError.malformed("minimum")
        }
        if let max = number(schema["maximum"]), let n = number(instance), n > max {
            throw ACPCodecError.malformed("maximum")
        }
        if let min = schema["minItems"] as? Int, let arr = instance as? [Any], arr.count < min {
            throw ACPCodecError.malformed("minItems")
        }
        if let props = schema["properties"] as? [String: Any], let obj = instance as? [String: Any] {
            for (k, v) in obj {
                if let sub = props[k] as? [String: Any] {
                    try validate(instance: v, schema: sub, path: path, doc: doc)
                }
            }
        }
        if let extra = schema["additionalProperties"] as? Bool, extra == false,
           let obj = instance as? [String: Any] {
            let props = schema["properties"] as? [String: Any] ?? [:]
            for key in obj.keys where props[key] == nil {
                throw ACPCodecError.malformed("additional property \(key)")
            }
        }
        if let items = schema["items"] as? [String: Any], let arr = instance as? [Any] {
            for item in arr {
                try validate(instance: item, schema: items, path: path, doc: doc)
            }
        }
        if let all = schema["allOf"] as? [[String: Any]] {
            for sub in all { try validate(instance: instance, schema: sub, path: path, doc: doc) }
        }
        if let any = schema["anyOf"] as? [[String: Any]] {
            if !any.contains(where: { (try? validate(instance: instance, schema: $0, path: path, doc: doc)) != nil }) {
                throw ACPCodecError.malformed("anyOf failed")
            }
        }
        if let one = schema["oneOf"] as? [[String: Any]] {
            let hits = one.filter { (try? validate(instance: instance, schema: $0, path: path, doc: doc)) != nil }.count
            if hits != 1 { throw ACPCodecError.malformed("oneOf failed") }
        }
        if let ifSchema = schema["if"] as? [String: Any] {
            let matched = (try? validate(instance: instance, schema: ifSchema, path: path, doc: doc)) != nil
            if matched {
                if let thenSchema = schema["then"] as? [String: Any] {
                    try validate(instance: instance, schema: thenSchema, path: path, doc: doc)
                }
            } else if let elseSchema = schema["else"] as? [String: Any] {
                try validate(instance: instance, schema: elseSchema, path: path, doc: doc)
            }
        }
    }

    /// Test helper for isolated schema fragments, including `if`/`then`/`else`.
    static func validateInstance(_ instance: Any, schema: [String: Any]) throws {
        try validate(instance: instance, schema: schema, path: "", doc: schema)
    }

    private static func jsonType(_ value: Any) -> String {
        if value is NSNull { return "null" }
        if let n = value as? NSNumber {
            if CFGetTypeID(n) == CFBooleanGetTypeID() { return "boolean" }
            let t = CFNumberGetType(n as CFNumber)
            switch t {
            case .floatType, .doubleType, .float32Type, .float64Type, .cgFloatType: return "number"
            default: return "integer"
            }
        }
        if value is String { return "string" }
        if value is [Any] { return "array" }
        if value is [String: Any] { return "object" }
        return "null"
    }

    private static func typeOk(_ got: String, _ wanted: String) -> Bool {
        got == wanted || (wanted == "number" && got == "integer")
    }

    private static func number(_ value: Any?) -> Double? {
        if let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() { return n.doubleValue }
        if let d = value as? Double { return d }
        if let i = value as? Int { return Double(i) }
        return nil
    }

    private static func jsonEqual(_ a: Any, _ b: Any) -> Bool {
        switch (a, b) {
        case let (x as String, y as String): return x == y
        case let (x as Bool, y as Bool): return x == y
        case let (x as NSNumber, y as NSNumber): return x == y
        default: return false
        }
    }
}
