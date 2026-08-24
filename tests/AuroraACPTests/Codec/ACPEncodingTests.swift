import XCTest
import AuroraACP

final class ACPEncodingTests: XCTestCase {
    func repoRoot() -> URL {
        RepoRoot.url()
    }

    func testGoldenVectors() throws {
        let root = repoRoot()
        let manifestURL = root.appendingPathComponent("vectors/manifest.json")
        let data = try Data(contentsOf: manifestURL)
        let manifest = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        let vectors = manifest["vectors"] as! [[String: Any]]
        for item in vectors {
            let id = item["id"] as! String
            let jsonRel = item["json"] as! String
            let cborRel = item["cbor"] as! String
            let jsonData = try Data(contentsOf: root.appendingPathComponent("vectors").appendingPathComponent(jsonRel))
            let pinned = try Data(contentsOf: root.appendingPathComponent("vectors").appendingPathComponent(cborRel))
            let env = try ACPEncoding.decodeJSON(jsonData)
            let encoded = try ACPEncoding.encodeCBOR(env)
            if encoded != pinned {
                let tmp = FileManager.default.temporaryDirectory
                try encoded.write(to: tmp.appendingPathComponent("swift-\(id).cbor"))
                try pinned.write(to: tmp.appendingPathComponent("pinned-\(id).cbor"))
                print("WROTE \(tmp.path) swift-\(id).cbor")
            }
            XCTAssertEqual(encoded, pinned, "cbor mismatch \(id)")
            let again: ACPEnvelope
            do {
                again = try ACPEncoding.decodeCBOR(pinned)
            } catch {
                XCTFail("CBOR decode failed for \(id): \(error)")
                continue
            }
            XCTAssertEqual(again, env, "decoded envelope mismatch \(id)")
            let jsonAgain = try ACPEncoding.encodeJSON(again)
            let viaJSON = try ACPEncoding.decodeJSON(jsonAgain)
            XCTAssertTrue(semanticallyEqual(viaJSON, env), "json re-encode mismatch \(id)")
        }
    }

    func semanticallyEqual(_ lhs: ACPEnvelope, _ rhs: ACPEnvelope) -> Bool {
        func norm(_ value: AnySendable) -> AnySendable {
            switch value {
            case .int(let i):
                return .int(i)
            case .uint(let u) where u <= UInt64(Int64.max):
                return .int(Int64(u))
            case .double(let d) where d.rounded() == d && d >= Double(Int64.min) && d <= Double(Int64.max):
                return .int(Int64(d))
            case .array(let items):
                return .array(items.map(norm))
            case .object(let obj):
                return .object(obj.mapValues(norm))
            default:
                return value
            }
        }
        var a = lhs
        var b = rhs
        a.payload = a.payload.mapValues(norm)
        b.payload = b.payload.mapValues(norm)
        return a == b
    }

    func testChunkBytesRoundtripAndRejectBadBase64() throws {
        let json = """
        {
          "acp":"1.2",
          "message_id":"0193f8d8-4c4e-7d8b-a2ab-000000000040",
          "type":"resource.chunk",
          "source":{"node_id":"0193f8d8-4c4e-7d8b-a2ab-000000000001"},
          "timestamp_utc":"2026-08-17T16:42:15.231Z",
          "qos":"reliable",
          "flags":[],
          "payload":{"transfer_id":"0193f8d8-4c4e-7d8b-a2ab-000000000070","offset":0,"length":4,"data":"AAH/4A=="}
        }
        """.data(using: .utf8)!
        let env = try ACPEncoding.decodeJSON(json)
        guard case .bytes(let bytes) = env.payload["data"] else {
            return XCTFail("expected decoded bytes")
        }
        XCTAssertEqual(bytes, Data([0x00, 0x01, 0xFF, 0xE0]))
        let cbor = try ACPEncoding.encodeCBOR(env)
        XCTAssertTrue(cbor.contains(0x44))
        let again = try ACPEncoding.decodeCBOR(cbor)
        XCTAssertEqual(again.payload["data"], env.payload["data"])
        let jsonAgain = try ACPEncoding.encodeJSON(again)
        let obj = try JSONSerialization.jsonObject(with: jsonAgain) as! [String: Any]
        let payload = obj["payload"] as! [String: Any]
        XCTAssertEqual(payload["data"] as? String, "AAH/4A==")
        let bad = String(data: json, encoding: .utf8)!.replacingOccurrences(of: "AAH/4A==", with: "!!!!")
        XCTAssertThrowsError(try ACPEncoding.decodeJSON(bad.data(using: .utf8)!))
    }

    func testInvalidCorpusRejected() throws {
        let dir = repoRoot().appendingPathComponent("vectors/invalid")
        let manifest = try JSONSerialization.jsonObject(with: Data(contentsOf: dir.appendingPathComponent("manifest.json"))) as! [String: Any]
        let vectors = manifest["vectors"] as! [[String: Any]]
        for item in vectors {
            let id = item["id"] as! String
            let rel = item["json"] as! String
            let expected = item["error"] as! String
            let data = try Data(contentsOf: repoRoot().appendingPathComponent("vectors").appendingPathComponent(rel))
            do {
                _ = try ACPEncoding.decodeJSON(data)
                XCTFail("expected reject \(id)")
            } catch {
                let text = String(describing: error)
                XCTAssertTrue(text.contains(expected), "\(id) \(text)")
            }
        }
    }

    func testMalformedCorpusRejected() throws {
        let dir = repoRoot().appendingPathComponent("vectors/malformed")
        let files = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "cbor" }
        XCTAssertGreaterThanOrEqual(files.count, 4)
        for url in files {
            let data = try Data(contentsOf: url)
            XCTAssertThrowsError(try ACPEncoding.decodeCBOR(data), url.lastPathComponent)
        }
    }
}
