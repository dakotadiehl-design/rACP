import XCTest
@testable import AuroraACP

final class ACPSecurityContractTests: XCTestCase {
    private let node = "0193f8d8-4c4e-7d8b-a2ab-000000000002"
    private let domain = "0193f8d8-4c4e-7d8b-a2ab-000000000090"
    private let digest = "sha256:" + String(repeating: "a", count: 64)
    private let binding = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

    private func evidence(
        state: ACPCredentialState = .active, verified: Bool = true,
        zeroRTT: Bool = false, resumed: Bool = false
    ) -> ACPTransportEvidence {
        ACPTransportEvidence(
            mode: .auroraTrust, trustDomainID: domain, nodeID: node, credentialID: digest,
            identityKeyID: digest, credentialFormat: "x509_der", channelBinding: binding,
            credentialState: state, channelBindingVerified: verified,
            zeroRTTUsed: zeroRTT, resumptionUsed: resumed
        )
    }

    private func auth() -> [String: String] {
        [
            "mode": "aurora_trust", "trust_domain_id": domain, "credential_id": digest,
            "identity_key_id": digest, "channel_binding": binding,
        ]
    }

    func testAuroraTrustClaimsRequireTransportEvidence() {
        XCTAssertThrowsError(try ACPSecurityAdmission.bindHello(
            claimedNodeID: node, auth: ["mode": "aurora_trust"], evidence: nil, hardened: true
        )) { XCTAssertEqual($0 as? ACPSecurityAdmissionError, .downgradeForbidden) }
    }

    func testAuthenticatedHelloBindsEveryIdentityField() throws {
        let principal = try ACPSecurityAdmission.bindHello(
            claimedNodeID: node, auth: auth(), evidence: evidence(), hardened: true,
            securityCapabilities: [("aurora-trust", "1.0")]
        )
        XCTAssertEqual(principal.state, .authenticated)
        XCTAssertEqual(principal.nodeID, node)
    }

    func testInvalidTransportStatesAndCapabilitiesFailClosed() {
        let cases: [(ACPTransportEvidence, ACPSecurityAdmissionError)] = [
            (evidence(state: .revoked), .credentialRevoked),
            (evidence(state: .expired), .credentialExpired),
            (evidence(verified: false), .authenticationFailed),
            (evidence(zeroRTT: true), .downgradeForbidden),
            (evidence(resumed: true), .downgradeForbidden),
        ]
        for (transport, expected) in cases {
            XCTAssertThrowsError(try ACPSecurityAdmission.bindHello(
                claimedNodeID: node, auth: auth(), evidence: transport, hardened: true,
                securityCapabilities: [("aurora-trust", "1.0")]
            )) { XCTAssertEqual($0 as? ACPSecurityAdmissionError, expected) }
        }
        XCTAssertThrowsError(try ACPSecurityAdmission.bindHello(
            claimedNodeID: node, auth: auth(), evidence: evidence(), hardened: true,
            securityCapabilities: []
        )) { XCTAssertEqual($0 as? ACPSecurityAdmissionError, .downgradeForbidden) }
        XCTAssertThrowsError(try ACPSecurityAdmission.bindHello(
            claimedNodeID: node, auth: auth(), evidence: evidence(), hardened: true,
            securityCapabilities: [("aurora-trust", "1.0"), ("aurora-trust", "1.0")]
        )) { XCTAssertEqual($0 as? ACPSecurityAdmissionError, .credentialInvalid) }
    }

    func testCapabilitiesCannotExpandPermissions() {
        XCTAssertEqual(ACPSecurityAdmission.effectivePermissions(
            credentialConstraints: ["observe", "control"], localPolicy: ["observe", "control"],
            capabilities: ["observe", "control", "admin"], safetyPolicy: ["observe"]
        ), ["observe"])
    }

    func testFrozenSecurityCatalogIsConsumed() {
        XCTAssertEqual(ACPSecurityCatalog.capabilities["security.enrollment"], "1.0")
        XCTAssertNotNil(ACPSecurityCatalog.errors["security.downgrade_forbidden"])
        XCTAssertEqual(ACPSecurityCatalog.limits(profile: "full")["concurrent_attempts"] as? Int, 2)
        XCTAssertEqual(ACPSecurityCatalog.limits(profile: "lightweight")["max_credential_bytes"] as? Int, 2048)
    }
}
