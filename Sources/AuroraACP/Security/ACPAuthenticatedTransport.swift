import CryptoKit
import Foundation

public let ACPHelloExporterLabel = "EXPORTER-Aurora-ACP-1.2-HELLO"

public protocol ACPTLSExporter: Sendable {
    func export(label: String, context: Data, length: Int) throws -> Data
}

public struct ACPFullTLSHandshake: Sendable {
    public let protocolVersion: String
    public let mutualAuthentication, isolatedTrustStore, peerCertificateValid: Bool
    public let localCredentialSelected, peerSANExtracted: Bool
    public let trustDomainID, nodeID, credentialID, identityKeyID: String
    public let roleConstraints: Set<String>
    public let credentialState: ACPCredentialState
    public let zeroRTTUsed, resumptionUsed: Bool
    public init(
        protocolVersion: String, mutualAuthentication: Bool, isolatedTrustStore: Bool,
        peerCertificateValid: Bool, localCredentialSelected: Bool, peerSANExtracted: Bool,
        trustDomainID: String, nodeID: String, credentialID: String, identityKeyID: String,
        roleConstraints: Set<String>, credentialState: ACPCredentialState,
        zeroRTTUsed: Bool = false, resumptionUsed: Bool = false
    ) {
        self.protocolVersion = protocolVersion; self.mutualAuthentication = mutualAuthentication
        self.isolatedTrustStore = isolatedTrustStore; self.peerCertificateValid = peerCertificateValid
        self.localCredentialSelected = localCredentialSelected; self.peerSANExtracted = peerSANExtracted
        self.trustDomainID = trustDomainID; self.nodeID = nodeID; self.credentialID = credentialID
        self.identityKeyID = identityKeyID; self.roleConstraints = roleConstraints
        self.credentialState = credentialState; self.zeroRTTUsed = zeroRTTUsed; self.resumptionUsed = resumptionUsed
    }
}

public enum ACPAuthenticatedTransport {
    private static func closed(_ source: [String: AnySendable], _ keys: [String]) throws -> [String: AnySendable] {
        var result: [String: AnySendable] = [:]
        for key in keys { guard let value = source[key] else { throw ACPSecurityAdmissionError.credentialInvalid }; result[key] = value }
        return result
    }
    private static func capabilities(_ value: AnySendable?) throws -> AnySendable {
        guard case .array(let values) = value else { throw ACPSecurityAdmissionError.credentialInvalid }
        return .array(try values.map { value in
            guard case .object(let fields) = value else { throw ACPSecurityAdmissionError.credentialInvalid }
            return .object(try closed(fields, ["id", "version"]))
        })
    }

    public static func helloExporterContext(_ hello: [String: AnySendable]) throws -> Data {
        guard case .object(let node) = hello["node"], case .object(let proto) = hello["protocol"],
              case .object(let auth) = hello["auth"], case .array = hello["encodings"],
              case .array = hello["profiles"], case .array = hello["capabilities"]
        else { throw ACPSecurityAdmissionError.credentialInvalid }
        var projectedAuth = try closed(auth, ["mode", "trust_domain_id", "credential_id", "identity_key_id", "security_capabilities"])
        projectedAuth["security_capabilities"] = try capabilities(projectedAuth["security_capabilities"])
        let projection: [String: AnySendable] = [
            "node": .object(try closed(node, ["node_id", "instance_id", "role", "name"])),
            "protocol": .object(try closed(proto, ["min", "max"])),
            "encodings": hello["encodings"]!, "profiles": hello["profiles"]!,
            "capabilities": try capabilities(hello["capabilities"]),
            "auth": .object(projectedAuth),
        ]
        return Data(SHA256.hash(data: try ACPEncoding.encodeValue(.plain(.object(projection)))))
    }

    public static func fullEvidence(
        hello: [String: AnySendable], handshake: ACPFullTLSHandshake, exporter: any ACPTLSExporter
    ) throws -> ACPTransportEvidence {
        guard handshake.protocolVersion == "TLSv1.3", handshake.mutualAuthentication,
              handshake.isolatedTrustStore, handshake.peerCertificateValid,
              handshake.localCredentialSelected, handshake.peerSANExtracted
        else { throw ACPSecurityAdmissionError.authenticationFailed }
        guard !handshake.zeroRTTUsed, !handshake.resumptionUsed else { throw ACPSecurityAdmissionError.downgradeForbidden }
        switch handshake.credentialState {
        case .active: break
        case .revoked: throw ACPSecurityAdmissionError.credentialRevoked
        case .expired: throw ACPSecurityAdmissionError.credentialExpired
        case .invalid: throw ACPSecurityAdmissionError.credentialInvalid
        }
        let exported = try exporter.export(label: ACPHelloExporterLabel, context: helloExporterContext(hello), length: 32)
        guard exported.count == 32, case .object(let auth) = hello["auth"],
              case .bytes(let claimed) = auth["channel_binding"],
              ACPSecurityContext.channelBindingsEqual(exported, claimed)
        else { throw ACPSecurityAdmissionError.authenticationFailed }
        return .init(
            mode: .auroraTrust, profile: .full, trustDomainID: handshake.trustDomainID,
            nodeID: handshake.nodeID, credentialID: handshake.credentialID,
            identityKeyID: handshake.identityKeyID, credentialFormat: "x509",
            channelBinding: ACPSecurityContext.base64URLEncode(exported), roleConstraints: handshake.roleConstraints,
            credentialState: .active, channelBindingVerified: true
        )
    }

    public static func parseLightweightPreface(
        _ data: Data, validate: (Data) throws -> ACPTransportEvidence
    ) throws -> (ACPTransportEvidence, Data) {
        guard data.count >= 3 else { throw ACPSecurityAdmissionError.credentialInvalid }
        let length = Int(data[0]) << 8 | Int(data[1])
        guard (1...2048).contains(length), data.count == length + 2 else {
            throw ACPSecurityAdmissionError.credentialInvalid
        }
        let credential = data.dropFirst(2)
        let evidence = try validate(Data(credential))
        guard evidence.profile == .lightweight, evidence.credentialState == .active else {
            throw ACPSecurityAdmissionError.credentialInvalid
        }
        return (evidence, Data(credential))
    }

    public static func verifyLightweightFinished(exportedKey: Data, context: Data, received: Data) throws {
        guard exportedKey.count == 32, context.count <= 8192, received.count == 32 else {
            throw ACPSecurityAdmissionError.authenticationFailed
        }
        let expected = Data(HMAC<SHA256>.authenticationCode(
            for: context, using: SymmetricKey(data: exportedKey)))
        guard ACPSecurityContext.channelBindingsEqual(expected, received) else {
            throw ACPSecurityAdmissionError.authenticationFailed
        }
    }
}
