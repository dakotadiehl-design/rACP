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
