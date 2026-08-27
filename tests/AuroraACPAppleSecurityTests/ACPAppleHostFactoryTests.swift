import AuroraACP
@testable import AuroraACPAppleSecurity
import XCTest

final class ACPAppleHostFactoryTests: XCTestCase {
    func testFactoryRejectsNamespaceAlreadyBoundToDifferentNodeBeforeCreatingAuthority() async throws {
        let suffix = UUID().uuidString.lowercased().prefix(20)
        let namespace = "com.aurora.acp.host-test.\(suffix)"
        let service = namespace + ".host-provisioning"
        let backend = ACPKeychainCredentialBackend(service: service)
        defer { try? backend.delete(name: "host-provisioning") }
        let journal = try ACPAppleHostProvisioningJournal(service: service)
        _ = try journal.loadOrReserve(nodeID: ACPSecurityNodeID(
            rawValue: "00112233-4455-4677-8899-aabbccddeeff")!)
        let configuration = try ACPAppleHostConfiguration(
            identity: ACPIdentity(
                nodeID: "10112233-4455-4677-8899-aabbccddeeff",
                role: "host", name: "Wrong Host"),
            storageNamespace: namespace,
            providerProvenance: try provenance())

        do {
            _ = try await ACPAppleHostFactory.openOrBootstrap(configuration: configuration)
            XCTFail("factory accepted a namespace bound to another node")
        } catch {
            XCTAssertEqual(error as? ACPAppleHostProvisioningError, .corruptState)
        }
    }

    private func provenance() throws -> ACPProviderProvenance {
        let json = """
        {"schema_version":"1.0","adapter_id":"apple.network-framework.full","source_revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","provider":{"name":"Network.framework","version":"macOS"},"target_triple":"arm64-apple-macosx","profiles":["full"],"key_storage_classes":["secure_enclave","keychain"],"qualification":{"status":"PASS","artifact_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}
        """
        return try ACPProviderProvenance(jsonData: Data(json.utf8))
    }
}
