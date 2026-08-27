import AuroraACP
import AuroraACPAppleSecurity
import Foundation
import Security

@main
enum ACPAppleFullQualificationHost {
    static func main() async {
        do { try await run(Array(CommandLine.arguments.dropFirst())) }
        catch {
            FileHandle.standardError.write(Data("qualification error: \(error)\n".utf8))
            Foundation.exit(1)
        }
    }

    private static func run(_ arguments: [String]) async throws {
        guard arguments.count >= 2 else { throw UsageError() }
        let mode = arguments[0]
        if mode == "authority-bootstrap" {
            guard arguments.count == 2 else { throw UsageError() }
            let service = arguments[1]
            let store = try ACPAppleTrustDomainAuthorityStore(
                applicationTag: Data("\(service).authority".utf8),
                metadataService: service + ".authority",
                keyMetadataService: service + ".authority-key")
            let authority = try await store.openOrCreate()
            emit([
                "status": "active",
                "trust_domain_id": authority.identity.trustDomainID.rawValue,
                "authority_key_id": authority.identity.authorityKeyID.rawValue,
                "anchor_credential_id": authority.identity.trustAnchorCredentialID.rawValue,
                "custody": authority.custody.rawValue,
                "anchor_der_base64": authority.anchorDER.base64EncodedString(),
            ])
            return
        }
        guard arguments.count >= 3 else { throw UsageError() }
        let fixture = URL(fileURLWithPath: arguments[1], isDirectory: true)
        let service = arguments[2]
        let values = try manifest(fixture)
        let root = try certificate(fixture.appendingPathComponent("root.der"))
        let domain = try required(ACPTrustDomainID(rawValue: values["domain"]!))
        let hostNode = try required(ACPSecurityNodeID(rawValue: values["host"]!))
        let clientNode = try required(ACPSecurityNodeID(rawValue: values["client"]!))
        let hostLabel = values["host_label"]!, clientLabel = values["client_label"]!
        let hostIdentity = ACPIdentity(nodeID: hostNode.rawValue, role: "prism", name: "Qualification Host")
        let clientIdentity = ACPIdentity(nodeID: clientNode.rawValue, role: "remote", name: "Qualification Client")
        let hostStore = ACPAppleIdentityStore(anchors: [root], trustDomainID: domain,
            referenceService: service + ".host-identity")
        let clientStore = ACPAppleIdentityStore(anchors: [root], trustDomainID: domain,
            referenceService: service + ".client-identity")

        switch mode {
        case "bootstrap":
            guard arguments.count == 3 else { throw UsageError() }
            let installedHost = try await hostStore.installIssuedPKCS12(
                Data(contentsOf: fixture.appendingPathComponent("host.p12")),
                password: values["password"]!, label: hostLabel, identity: hostIdentity)
            let installedClient = try await clientStore.installIssuedPKCS12(
                Data(contentsOf: fixture.appendingPathComponent("client.p12")),
                password: values["password"]!, label: clientLabel, identity: clientIdentity)
            let hostTrust = try ACPAppleTrustedPeerStore(
                service: service + ".host-trust", account: "peers")
            let clientTrust = try ACPAppleTrustedPeerStore(
                service: service + ".client-trust", account: "peers")
            try commitFixtureTrust(installedClient, in: hostTrust)
            try commitFixtureTrust(installedHost, in: clientTrust)
            emit(["status": "bootstrapped"])
        case "server":
            guard arguments.count == 3 else { throw UsageError() }
            let local = try await hostStore.load(label: hostLabel, identity: hostIdentity)
            let trust = try ACPAppleTrustedPeerStore(service: service + ".host-trust", account: "peers")
            let configuration = ACPAppleFullProviderConfiguration(localIdentity: local, anchors: [root],
                trustDomainID: domain, expectedPeerNodeID: clientNode,
                providerProvenance: try provenance(), trustStore: trust)
            let listener = try ACPAppleFullServerFactory.makeListener(configuration: configuration)
            try await listener.start()
            emit(["port": String(await listener.endpoint.port)])
            let authenticated = try await listener.accept(timeout: 10)
            let session = try authenticated.makeSession(local: hostIdentity)
            _ = try await session.handshake()
            let peer = try required(await session.peer?.nodeID)
            emit(["peer": peer, "status": "authenticated"])
            await session.goodbye(); await listener.shutdown()
        case "client":
            guard arguments.count == 4, let port = UInt16(arguments[3]) else { throw UsageError() }
            let local = try await clientStore.load(label: clientLabel, identity: clientIdentity)
            let trust = try ACPAppleTrustedPeerStore(service: service + ".client-trust", account: "peers")
            let configuration = ACPAppleFullProviderConfiguration(localIdentity: local, anchors: [root],
                trustDomainID: domain, expectedPeerNodeID: hostNode,
                providerProvenance: try provenance(), trustStore: trust)
            let authenticated = try await ACPAppleFullConnectionFactory.connect(
                host: "127.0.0.1", port: port, configuration: configuration)
            let session = try authenticated.makeSession(local: clientIdentity)
            _ = try await session.handshake()
            let peer = try required(await session.peer?.nodeID)
            emit(["peer": peer, "status": "authenticated"])
            await session.goodbye()
        case "revoke":
            guard arguments.count == 3 else { throw UsageError() }
            let trust = try ACPAppleTrustedPeerStore(service: service + ".host-trust", account: "peers")
            guard let raw = trust.trustedPeers().first(where: { $0.nodeID == clientNode.rawValue })?.credentialID,
                  let credential = ACPCredentialID(rawValue: raw) else {
                throw ACPAppleSecurityError.trustStoreFailure
            }
            emit(["status": try trust.revoke(credential).rawValue])
        case "cleanup":
            guard arguments.count == 3 else { throw UsageError() }
            try await hostStore.reset(label: hostLabel); try await clientStore.reset(label: clientLabel)
            try ACPAppleTrustedPeerStore(service: service + ".host-trust", account: "peers").reset()
            try ACPAppleTrustedPeerStore(service: service + ".client-trust", account: "peers").reset()
            emit(["status": "clean"])
        default: throw UsageError()
        }
    }

    private static func manifest(_ directory: URL) throws -> [String: String] {
        guard let values = try JSONSerialization.jsonObject(
            with: Data(contentsOf: directory.appendingPathComponent("manifest.json"))) as? [String: String]
        else { throw UsageError() }
        return values
    }

    private static func certificate(_ url: URL) throws -> SecCertificate {
        guard let value = SecCertificateCreateWithData(nil, try Data(contentsOf: url) as CFData)
        else { throw ACPAppleSecurityError.malformedIdentity }
        return value
    }

    private static func required<T>(_ value: T?) throws -> T {
        guard let value else { throw UsageError() }; return value
    }

    private static func emit(_ values: [String: String]) {
        let data = try! JSONSerialization.data(withJSONObject: values, options: [.sortedKeys])
        FileHandle.standardOutput.write(data + Data([0x0a]))
    }

    private static func provenance() throws -> ACPProviderProvenance {
        let json = """
        {"schema_version":"1.0","adapter_id":"apple.network-framework.full","source_revision":"\(String(repeating: "a", count: 40))","provider":{"name":"Network.framework","version":"macOS"},"target_triple":"arm64-apple-macosx","profiles":["full"],"key_storage_classes":["keychain"],"qualification":{"status":"PASS","artifact_sha256":"\(String(repeating: "b", count: 64))"}}
        """
        return try ACPProviderProvenance(jsonData: Data(json.utf8))
    }

    private static func commitFixtureTrust(
        _ identity: ACPAppleLocalIdentity, in store: ACPAppleTrustedPeerStore
    ) throws {
        let metadata = identity.metadata
        let certificate = ACPAppleVerifiedCertificate(
            trustDomainID: try required(ACPTrustDomainID(rawValue: metadata.trustDomainID)),
            nodeID: try required(ACPSecurityNodeID(rawValue: metadata.nodeID)),
            credentialID: try required(ACPCredentialID(rawValue: metadata.credentialID)),
            identityKeyID: try required(ACPIdentityKeyID(rawValue: metadata.identityKeyID)),
            leafDER: SecCertificateCopyData(identity.certificateChain[0]) as Data)
        try store.recordPending(certificate, displayName: nil)
        try store.activatePending(certificate.credentialID)
    }
}

private struct UsageError: Error { }
