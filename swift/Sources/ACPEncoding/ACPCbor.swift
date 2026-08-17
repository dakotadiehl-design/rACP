import Foundation
import ACPModel

enum CborValue {
    case plain(AnySendable)
    case tag0(String)
}

extension ACPEncoding {
    static func cborReady(_ value: AnySendable) -> CborValue {
        guard case .object = value else { return .plain(value) }
        return .plain(value)
    }

    static func encodeValue(_ prepared: CborValue) throws -> Data {
        switch prepared {
        case .plain(let v):
            if case .object(let o) = v {
                return try encodeObject(o, tagTimestamp: true)
            }
            return try encodePlain(v)
        case .tag0(let s):
            return Data([0xC0]) + (try encodePlain(.string(s)))
        }
    }

    static func encodePlain(_ value: AnySendable) throws -> Data {
        switch value {
        case .null: return Data([0xF6])
        case .bool(false): return Data([0xF4])
        case .bool(true): return Data([0xF5])
        case .int(let n) where n >= 0:
            return head(0, UInt64(n))
        case .int(let n):
            return head(1, UInt64(-1 - n))
        case .uint(let n):
            return head(0, n)
        case .double(let f):
            guard f.isFinite else { throw ACPCodecError.malformed("nan") }
            var be = f.bitPattern.bigEndian
            var data = Data([0xFB])
            withUnsafeBytes(of: &be) { data.append(contentsOf: $0) }
            return data
        case .string(let s):
            let raw = Data(s.utf8)
            return head(3, UInt64(raw.count)) + raw
        case .bytes(let b):
            return head(2, UInt64(b.count)) + b
        case .array(let items):
            var data = head(4, UInt64(items.count))
            for item in items { data += try encodePlain(item) }
            return data
        case .object(let o):
            return try encodeObject(o, tagTimestamp: false)
        }
    }

    static func encodeObject(_ o: [String: AnySendable], tagTimestamp: Bool) throws -> Data {
        var pairs: [(Data, Data)] = []
        for (k, v) in o {
            let key = try encodePlain(.string(k))
            let val: Data
            if tagTimestamp, k == "timestamp_utc", case .string(let s) = v {
                val = Data([0xC0]) + (try encodePlain(.string(s)))
            } else {
                val = try encodePlain(v)
            }
            pairs.append((key, val))
        }
        pairs.sort { $0.0.lexicographicallyPrecedes($1.0) }
        var data = head(5, UInt64(pairs.count))
        for (k, v) in pairs {
            data += k
            data += v
        }
        return data
    }

    static func head(_ major: UInt8, _ n: UInt64) -> Data {
        if n < 24 { return Data([(major << 5) | UInt8(n)]) }
        if n < 256 { return Data([(major << 5) | 24, UInt8(n)]) }
        if n < 65536 {
            var be = UInt16(n).bigEndian
            var d = Data([(major << 5) | 25])
            withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
            return d
        }
        if n < UInt64(UInt32.max) + 1 {
            var be = UInt32(n).bigEndian
            var d = Data([(major << 5) | 26])
            withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
            return d
        }
        var be = n.bigEndian
        var d = Data([(major << 5) | 27])
        withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
        return d
    }

    static func decodeValue(_ data: Data) throws -> AnySendable {
        var offset = 0
        let value = try readValue(data, &offset)
        if offset != data.count { throw ACPCodecError.malformed("trailing") }
        return value
    }

    static let maxNesting = 16
    static let maxItems: UInt64 = 1_048_576
    static let maxBytes: UInt64 = 8 * 1024 * 1024

    static func boundedCount(_ n: UInt64, max: UInt64) throws -> Int {
        guard n <= max, n <= UInt64(Int.max) else { throw ACPCodecError.malformed("length") }
        return Int(n)
    }

    static func readValue(_ data: Data, _ offset: inout Int, depth: Int = 0) throws -> AnySendable {
        if depth > maxNesting { throw ACPCodecError.malformed("nesting") }
        guard offset < data.count else { throw ACPCodecError.malformed("truncated") }
        let initial = data[offset]
        offset += 1
        let major = initial >> 5
        let ai = initial & 0x1F
        if ai == 31 { throw ACPCodecError.malformed("indefinite") }
        switch major {
        case 0:
            let n = try readArg(data, ai, &offset)
            guard n <= UInt64(Int64.max) else { throw ACPCodecError.malformed("int range") }
            return .int(Int64(n))
        case 1:
            let n = try readArg(data, ai, &offset)
            guard n <= UInt64(Int64.max) else { throw ACPCodecError.malformed("int range") }
            return .int(-1 - Int64(n))
        case 2:
            let n = try boundedCount(try readArg(data, ai, &offset), max: maxBytes)
            let slice = try slice(data, offset, n)
            offset += n
            return .bytes(slice)
        case 3:
            let n = try boundedCount(try readArg(data, ai, &offset), max: maxBytes)
            let slice = try slice(data, offset, n)
            offset += n
            guard let s = String(data: slice, encoding: .utf8) else {
                throw ACPCodecError.malformed("utf8")
            }
            return .string(s)
        case 4:
            let n = try boundedCount(try readArg(data, ai, &offset), max: maxItems)
            var items: [AnySendable] = []
            items.reserveCapacity(n)
            for _ in 0..<n { items.append(try readValue(data, &offset, depth: depth + 1)) }
            return .array(items)
        case 5:
            let n = try boundedCount(try readArg(data, ai, &offset), max: maxItems)
            var obj: [String: AnySendable] = [:]
            var lastKey: Data?
            for _ in 0..<n {
                let keyStart = offset
                guard case .string(let k) = try readValue(data, &offset, depth: depth + 1) else {
                    throw ACPCodecError.malformed("key")
                }
                let encoded = data.subdata(in: keyStart..<offset)
                if let prev = lastKey {
                    if encoded.lexicographicallyPrecedes(prev) { throw ACPCodecError.malformed("key order") }
                    if encoded == prev { throw ACPCodecError.malformed("duplicate key") }
                }
                lastKey = encoded
                if obj[k] != nil { throw ACPCodecError.malformed("duplicate key") }
                obj[k] = try readValue(data, &offset, depth: depth + 1)
            }
            return .object(obj)
        case 6:
            let tag = try readArg(data, ai, &offset)
            if tag != 0 { throw ACPCodecError.malformed("tag") }
            let inner = try readValue(data, &offset, depth: depth + 1)
            return inner
        case 7:
            switch ai {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            case 27:
                let slice = try slice(data, offset, 8)
                offset += 8
                let bits = slice.withUnsafeBytes { $0.load(as: UInt64.self).bigEndian }
                let f = Double(bitPattern: bits)
                if !f.isFinite { throw ACPCodecError.malformed("nan") }
                return .double(f)
            default:
                throw ACPCodecError.malformed("simple")
            }
        default:
            throw ACPCodecError.malformed("major")
        }
    }

    static func readArg(_ data: Data, _ ai: UInt8, _ offset: inout Int) throws -> UInt64 {
        if ai < 24 { return UInt64(ai) }
        if ai == 24 {
            guard offset < data.count else { throw ACPCodecError.malformed("truncated") }
            let v = data[offset]
            offset += 1
            if v < 24 { throw ACPCodecError.malformed("non-preferred") }
            return UInt64(v)
        }
        if ai == 25 {
            let s = try slice(data, offset, 2)
            offset += 2
            let n = UInt64(s[0]) << 8 | UInt64(s[1])
            if n < 256 { throw ACPCodecError.malformed("non-preferred") }
            return n
        }
        if ai == 26 {
            let s = try slice(data, offset, 4)
            offset += 4
            let n = UInt64(s[0]) << 24 | UInt64(s[1]) << 16 | UInt64(s[2]) << 8 | UInt64(s[3])
            if n < 65536 { throw ACPCodecError.malformed("non-preferred") }
            return n
        }
        if ai == 27 {
            let s = try slice(data, offset, 8)
            offset += 8
            var v: UInt64 = 0
            for b in s { v = (v << 8) | UInt64(b) }
            if v < (UInt64(1) << 32) { throw ACPCodecError.malformed("non-preferred") }
            return v
        }
        throw ACPCodecError.malformed("ai")
    }

    static func slice(_ data: Data, _ offset: Int, _ n: Int) throws -> Data {
        guard n >= 0 else { throw ACPCodecError.malformed("truncated") }
        let (end, overflow) = offset.addingReportingOverflow(n)
        guard !overflow, end <= data.count else { throw ACPCodecError.malformed("truncated") }
        return data.subdata(in: offset..<end)
    }

    static func ns(_ value: AnySendable) -> Any {
        switch value {
        case .null: return NSNull()
        case .bool(let b): return b
        case .int(let i): return i
        case .uint(let u): return u
        case .double(let d): return d
        case .string(let s): return s
        case .bytes(let b): return b.base64EncodedString()
        case .array(let a): return a.map(ns)
        case .object(let o):
            var d: [String: Any] = [:]
            for (k, v) in o { d[k] = ns(v) }
            return d
        }
    }

    static func fromNS(_ value: Any) -> AnySendable {
        // NSNumber bridges to Bool/Int; inspect it before those casts.
        if value is NSNull { return .null }
        if let n = value as? NSNumber {
            if CFGetTypeID(n) == CFBooleanGetTypeID() {
                return .bool(n.boolValue)
            }
            let numberType = CFNumberGetType(n as CFNumber)
            switch numberType {
            case .floatType, .doubleType, .float32Type, .float64Type, .cgFloatType:
                return .double(n.doubleValue)
            default:
                return .int(n.int64Value)
            }
        }
        if let s = value as? String { return .string(s) }
        if let a = value as? [Any] { return .array(a.map(fromNS)) }
        if let o = value as? [String: Any] {
            var d: [String: AnySendable] = [:]
            for (k, v) in o { d[k] = fromNS(v) }
            return .object(d)
        }
        return .null
    }
}
