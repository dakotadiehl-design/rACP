import AuroraACP
import Foundation
import Security
import XCTest
@testable import AuroraACPAppleSecurity

final class ACPAppleIdentityStoreTests: XCTestCase {
    func testIssuedIdentityInstallReloadDuplicateAndResetUseRealKeychain() async throws {
        let label = "Aurora S10 Test \(UUID().uuidString)"
        let fixture = try makeFixture(label: label)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let root = try XCTUnwrap(SecCertificateCreateWithData(
            nil, try Data(contentsOf: fixture.directory.appendingPathComponent("root.der")) as CFData))
        let store = ACPAppleIdentityStore(
            anchors: [root], trustDomainID: ACPTrustDomainID(rawValue: fixture.domain)!)
        let identity = ACPIdentity(nodeID: fixture.host, role: "prism", name: "Qualification Host")
        defer { Task { try? await store.reset(label: label) } }
        let rejectedLabel = label + " rejected"
        await XCTAssertThrowsErrorAsync {
            _ = try await store.installIssuedPKCS12(
                Data(contentsOf: fixture.directory.appendingPathComponent("host.p12")),
                password: "wrong-password", label: rejectedLabel, identity: identity)
        }
        await XCTAssertThrowsErrorAsync { _ = try await store.load(label: rejectedLabel, identity: identity) }
        let installed = try await store.installIssuedPKCS12(
            Data(contentsOf: fixture.directory.appendingPathComponent("host.p12")),
            password: fixture.password, label: label, identity: identity)
        XCTAssertEqual(installed.metadata.nodeID, fixture.host)
        let restored = try await store.load(label: label, identity: identity)
        XCTAssertEqual(restored.metadata, installed.metadata)
        await XCTAssertThrowsErrorAsync {
            _ = try await store.installIssuedPKCS12(
                Data(contentsOf: fixture.directory.appendingPathComponent("host.p12")),
                password: fixture.password, label: label, identity: identity)
        }
        try await store.reset(label: label)
        await XCTAssertThrowsErrorAsync { _ = try await store.load(label: label, identity: identity) }
    }

    func testMalformedStaleAndWrongClassIdentityLocatorsFailClosed() async throws {
        let label = "Aurora S10 Locator Test \(UUID().uuidString)"
        let fixture = try makeFixture(label: label)
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let root = try XCTUnwrap(SecCertificateCreateWithData(
            nil, try Data(contentsOf: fixture.directory.appendingPathComponent("root.der")) as CFData))
        let service = "com.aurora.acp.tests.identity.\(UUID().uuidString)"
        let backend = ACPKeychainCredentialBackend(service: service)
        let store = ACPAppleIdentityStore(anchors: [root],
            trustDomainID: ACPTrustDomainID(rawValue: fixture.domain)!, referenceService: service)
        let identity = ACPIdentity(nodeID: fixture.host, role: "prism", name: "Qualification Host")
        _ = try await store.installIssuedPKCS12(
            Data(contentsOf: fixture.directory.appendingPathComponent("host.p12")),
            password: fixture.password, label: label, identity: identity)
        let valid = try XCTUnwrap(backend.read(name: label))
        defer {
            try? backend.write(name: label, data: valid)
            Task { try? await store.reset(label: label) }
        }

        try backend.write(name: label, data: Data("not-json".utf8))
        await XCTAssertThrowsErrorAsync { _ = try await store.load(label: label, identity: identity) }

        let fields = try XCTUnwrap(try JSONSerialization.jsonObject(with: valid) as? [String: String])
        let wrongClass = try JSONSerialization.data(withJSONObject: [
            "certificate": fields["privateKey"]!, "privateKey": fields["certificate"]!,
        ], options: [.sortedKeys])
        try backend.write(name: label, data: wrongClass)
        await XCTAssertThrowsErrorAsync { _ = try await store.load(label: label, identity: identity) }

        let stale = try JSONSerialization.data(withJSONObject: [
            "certificate": Data(repeating: 0xa5, count: 32).base64EncodedString(),
            "privateKey": Data(repeating: 0x5a, count: 32).base64EncodedString(),
        ], options: [.sortedKeys])
        try backend.write(name: label, data: stale)
        await XCTAssertThrowsErrorAsync { _ = try await store.load(label: label, identity: identity) }

        try backend.write(name: label, data: valid)
        let restored = try await store.load(label: label, identity: identity)
        XCTAssertEqual(restored.metadata.nodeID, fixture.host)
        try await store.reset(label: label)
    }

    private func makeFixture(label: String) throws -> (directory: URL, domain: String, host: String, password: String) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", root.appendingPathComponent("scripts/apple_full_qualification_fixtures.py").path,
                             directory.path, "--host-label", label]
        try process.run(); process.waitUntilExit()
        XCTAssertEqual(process.terminationStatus, 0)
        let manifest = try JSONSerialization.jsonObject(
            with: Data(contentsOf: directory.appendingPathComponent("manifest.json"))) as! [String: String]
        return (directory, manifest["domain"]!, manifest["host"]!, manifest["password"]!)
    }
}

private func XCTAssertThrowsErrorAsync(_ operation: () async throws -> Void,
                                       file: StaticString = #filePath, line: UInt = #line) async {
    do { try await operation(); XCTFail("expected error", file: file, line: line) }
    catch { }
}
