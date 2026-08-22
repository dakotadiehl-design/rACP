import XCTest
@testable import AuroraACP

final class ACPSecurityContractTests: XCTestCase {
    private let node = "0193f8d8-4c4e-7d8b-a2ab-000000000002"
    private let domain = "0193f8d8-4c4e-7d8b-a2ab-000000000090"
    private let digest = "sha256:" + String(repeating: "a", count: 64)

    func testAuroraTrustClaimsRequireTransportEvidence() {
        XCTAssertThrowsError(try ACPSecurityAdmission.bindHello(
            claimedNodeID: node, auth: ["mode": "aurora_trust"], evidence: nil, hardened: true
        )) { XCTAssertEqual($0 as? ACPSecurityAdmissionError, .downgradeForbidden) }
    }

    func testAuthenticatedHelloBindsEveryIdentityField() throws {
        let evidence = ACPTransportEvidence(
            mode: .auroraTrust, trustDomainID: domain, nodeID: node, credentialID: digest,
            identityKeyID: digest, credentialFormat: "x509_der", channelBinding: "AQIDBA"
        )
        let auth = [
            "mode": "aurora_trust", "trust_domain_id": domain, "credential_id": digest,
            "identity_key_id": digest, "channel_binding": "AQIDBA",
        ]
        let principal = try ACPSecurityAdmission.bindHello(
            claimedNodeID: node, auth: auth, evidence: evidence, hardened: true
        )
        XCTAssertEqual(principal.state, .authenticated)
        XCTAssertEqual(principal.nodeID, node)
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
