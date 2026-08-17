import XCTest
import ACPEncoding

final class ACPEncodingTests: XCTestCase {
    func repoRoot() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<4 { url.deleteLastPathComponent() }
        return url
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
            let again = try ACPEncoding.decodeCBOR(pinned)
            XCTAssertEqual(again.type, env.type)
            XCTAssertEqual(again.messageID, env.messageID)
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
