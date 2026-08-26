import AuroraACP
import Foundation
import Security
import XCTest
@testable import AuroraACPAppleSecurity

final class ACPAppleFullAllUpTests: XCTestCase {
    func testRealKeychainTLS13MTLSExporterHelloAndSessions() async throws {
        let fixture = try makeFixture()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let root = try XCTUnwrap(SecCertificateCreateWithData(
            nil, try Data(contentsOf: fixture.directory.appendingPathComponent("root.der")) as CFData))
        let hostTrust = try ACPAppleTrustedPeerStore(
            service: fixture.service + ".host-trust", account: "peers")
        let clientTrust = try ACPAppleTrustedPeerStore(
            service: fixture.service + ".client-trust", account: "peers")
        let hostStore = ACPAppleIdentityStore(
            anchors: [root], trustDomainID: ACPTrustDomainID(rawValue: fixture.domain)!,
            referenceService: fixture.service + ".host-identity")
        let clientStore = ACPAppleIdentityStore(
            anchors: [root], trustDomainID: ACPTrustDomainID(rawValue: fixture.domain)!,
            referenceService: fixture.service + ".client-identity")
        let hostACP = ACPIdentity(nodeID: fixture.host, role: "prism", name: "Qualification Host")
        let clientACP = ACPIdentity(nodeID: fixture.client, role: "remote", name: "Qualification Client")
        let hostIdentity = try await hostStore.installIssuedPKCS12(
            Data(contentsOf: fixture.directory.appendingPathComponent("host.p12")),
            password: fixture.password, label: fixture.hostLabel, identity: hostACP)
        let clientIdentity = try await clientStore.installIssuedPKCS12(
            Data(contentsOf: fixture.directory.appendingPathComponent("client.p12")),
            password: fixture.password, label: fixture.clientLabel, identity: clientACP)
        let domain = ACPTrustDomainID(rawValue: fixture.domain)!
        let hostConfiguration = ACPAppleFullProviderConfiguration(
            localIdentity: hostIdentity, anchors: [root], trustDomainID: domain,
            expectedPeerNodeID: ACPSecurityNodeID(rawValue: fixture.client)!,
            providerProvenance: try provenance(), trustStore: hostTrust)
        let clientConfiguration = ACPAppleFullProviderConfiguration(
            localIdentity: clientIdentity, anchors: [root], trustDomainID: domain,
            expectedPeerNodeID: ACPSecurityNodeID(rawValue: fixture.host)!,
            providerProvenance: try provenance(), trustStore: clientTrust)
        let listener = try ACPAppleFullServerFactory.makeListener(configuration: hostConfiguration)
        try await listener.start()
        let port = await listener.endpoint.port
        let serverTask = Task { try await acceptSession(listener, local: hostACP) }
        let authenticatedClient: ACPAuthenticatedConnection
        do { authenticatedClient = try await ACPAppleFullConnectionFactory.connect(
            host: "127.0.0.1", port: port, configuration: clientConfiguration) }
        catch { throw NSError(
            domain: "ACPAppleFullAllUpTests.clientConnect", code: 1,
            userInfo: [NSUnderlyingErrorKey: error]) }
        let clientSession = try authenticatedClient.makeSession(local: clientACP)
        let acceptedPeer = try await serverTask.value
        do { _ = try await clientSession.handshake() }
        catch {
            let detail = (error as? ACPSessionError).map { "\($0.code): \($0.message)" } ?? String(describing: error)
            throw NSError(
            domain: "ACPAppleFullAllUpTests.clientSession", code: 2,
            userInfo: [NSUnderlyingErrorKey: error, NSLocalizedDescriptionKey: detail])
        }
        let clientPeer = await clientSession.peer?.nodeID
        XCTAssertEqual(clientPeer, fixture.host)
        XCTAssertEqual(acceptedPeer, fixture.client)
        await clientSession.goodbye()
        await listener.shutdown()
        XCTAssertEqual(hostTrust.trustedPeers().first?.nodeID, fixture.client)
        XCTAssertEqual(clientTrust.trustedPeers().first?.nodeID, fixture.host)

        let credential = try XCTUnwrap(hostTrust.trustedPeers().first?.credentialID)
        let credentialID = try XCTUnwrap(ACPCredentialID(rawValue: credential))
        let restoredHostTrust = try ACPAppleTrustedPeerStore(
            service: fixture.service + ".host-trust", account: "peers")
        XCTAssertEqual(try restoredHostTrust.revoke(credentialID), .revoked)
        let revokedHostConfiguration = ACPAppleFullProviderConfiguration(
            localIdentity: hostIdentity, anchors: [root], trustDomainID: domain,
            expectedPeerNodeID: ACPSecurityNodeID(rawValue: fixture.client)!,
            providerProvenance: try provenance(), trustStore: restoredHostTrust)
        let revokedListener = try ACPAppleFullServerFactory.makeListener(
            configuration: revokedHostConfiguration)
        try await revokedListener.start()
        let revokedPort = await revokedListener.endpoint.port
        let rejectedServer = Task { try await revokedListener.accept(timeout: 2) }
        await XCTAssertThrowsErrorAsync {
            _ = try await ACPAppleFullConnectionFactory.connect(
                host: "127.0.0.1", port: revokedPort,
                configuration: clientConfiguration, timeout: 2)
        }
        await XCTAssertThrowsErrorAsync { _ = try await rejectedServer.value }
        await revokedListener.shutdown()

        try await hostStore.reset(label: fixture.hostLabel)
        try await clientStore.reset(label: fixture.clientLabel)
        try hostTrust.reset(); try clientTrust.reset()
    }

    private func acceptSession(_ listener: ACPAppleFullServerListener,
                               local: ACPIdentity) async throws -> String? {
        let connection = try await listener.accept()
        let session = try connection.makeSession(local: local)
        _ = try await session.handshake()
        let peer = await session.peer?.nodeID
        await session.goodbye()
        return peer
    }

    private func provenance() throws -> ACPProviderProvenance {
        let json = """
        {"schema_version":"1.0","adapter_id":"apple.network-framework.full","source_revision":"\(String(repeating: "a", count: 40))","provider":{"name":"Network.framework","version":"macOS"},"target_triple":"arm64-apple-macosx","profiles":["full"],"key_storage_classes":["keychain"],"qualification":{"status":"PASS","artifact_sha256":"\(String(repeating: "b", count: 64))"}}
        """
        return try ACPProviderProvenance(jsonData: Data(json.utf8))
    }

    private func makeFixture() throws -> Fixture {
        let id = UUID().uuidString
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(id)
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent()
        let hostLabel = "Aurora S10 Host \(id)", clientLabel = "Aurora S10 Client \(id)"
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = ["python3", root.appendingPathComponent("scripts/apple_full_qualification_fixtures.py").path,
                             directory.path, "--host-label", hostLabel, "--client-label", clientLabel]
        try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus, 0)
        let values = try JSONSerialization.jsonObject(
            with: Data(contentsOf: directory.appendingPathComponent("manifest.json"))) as! [String: String]
        return Fixture(directory: directory, service: "com.aurora.acp.tests.\(id)", domain: values["domain"]!,
                       host: values["host"]!, client: values["client"]!, password: values["password"]!,
                       hostLabel: hostLabel, clientLabel: clientLabel)
    }
}

private struct Fixture {
    let directory: URL, service: String, domain: String, host: String, client: String, password: String
    let hostLabel: String, clientLabel: String
}

private func XCTAssertThrowsErrorAsync(_ operation: () async throws -> Void,
                                       file: StaticString = #filePath, line: UInt = #line) async {
    do { try await operation(); XCTFail("expected error", file: file, line: line) }
    catch { }
}
