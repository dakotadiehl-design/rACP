import Foundation

struct Probe: Codable {
    let id: String
    let status: String
    let detail: String
    let mandatory = true
}

let node = "00112233-4455-4677-8899-aabbccddeeff"
let domain = "40516273-8495-4a6b-8a3b-4c5d6e7f8091"
let credential = "sha256:" + String(repeating: "a", count: 64)
let key = "sha256:" + String(repeating: "b", count: 64)
let binding = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
let capabilities = [(id: "aurora-trust", version: "1.0")]
let valid = [
    "mode": "aurora_trust", "trust_domain_id": domain, "credential_id": credential,
    "identity_key_id": key, "channel_binding": binding,
]

func evidence(
    state: ACPCredentialState = .active, bindingVerified: Bool = true,
    zeroRTT: Bool = false, resumed: Bool = false
) -> ACPTransportEvidence {
    ACPTransportEvidence(
        mode: .auroraTrust, trustDomainID: domain, nodeID: node,
        credentialID: credential, identityKeyID: key, credentialFormat: "x509_der",
        channelBinding: binding, credentialState: state,
        channelBindingVerified: bindingVerified, zeroRTTUsed: zeroRTT,
        resumptionUsed: resumed
    )
}

func rejects(
    _ id: String, auth: [String: String] = valid,
    transport: ACPTransportEvidence? = evidence(), claimedNode: String = node,
    advertised: [(id: String, version: String)] = capabilities,
    expected: ACPSecurityAdmissionError
) -> Probe {
    do {
        _ = try ACPSecurityAdmission.bindHello(
            claimedNodeID: claimedNode, auth: auth, evidence: transport,
            hardened: true, securityCapabilities: advertised
        )
        return Probe(id: id, status: "FAIL", detail: "admission unexpectedly succeeded")
    } catch let error as ACPSecurityAdmissionError {
        let pass = error == expected
        return Probe(
            id: id, status: pass ? "PASS" : "FAIL",
            detail: pass ? "rejected with \(error.rawValue)" : "expected \(expected.rawValue), got \(error.rawValue)"
        )
    } catch {
        return Probe(id: id, status: "FAIL", detail: "unexpected error type: \(error)")
    }
}

@main
struct Main {
    static func main() throws {
        let probes = [
            rejects("network.missing_client_credential", transport: nil, expected: .downgradeForbidden),
            rejects(
                "network.wrong_trust_domain",
                auth: valid.merging(["trust_domain_id": "00000000-0000-4000-8000-000000000000"]) { _, new in new },
                expected: .trustDomainMismatch
            ),
            rejects(
                "network.wrong_node_identity", claimedNode: "00000000-0000-4000-8000-000000000000",
                expected: .identityMismatch
            ),
            rejects(
                "network.invalid_hello_channel_binding",
                auth: valid.merging(["channel_binding": "wrong"]) { _, new in new },
                expected: .identityMismatch
            ),
            rejects("network.stripped_trust_capability", advertised: [], expected: .downgradeForbidden),
            rejects(
                "network.duplicate_trust_capability",
                advertised: capabilities + [(id: "aurora-trust", version: "1.0")],
                expected: .credentialInvalid
            ),
            rejects(
                "network.trusted_lan_fallback", auth: ["mode": "trusted_lan"], transport: nil,
                advertised: [], expected: .downgradeForbidden
            ),
            rejects(
                "network.unverified_channel_binding", transport: evidence(bindingVerified: false),
                expected: .authenticationFailed
            ),
            rejects(
                "network.revoked_credential_reconnect", transport: evidence(state: .revoked),
                expected: .credentialRevoked
            ),
            rejects(
                "network.expired_credential_reconnect", transport: evidence(state: .expired),
                expected: .credentialExpired
            ),
            rejects(
                "network.zero_rtt_rejected", transport: evidence(zeroRTT: true),
                expected: .downgradeForbidden
            ),
            rejects(
                "network.resumption_disabled", transport: evidence(resumed: true),
                expected: .downgradeForbidden
            ),
        ]

        FileHandle.standardOutput.write(try JSONEncoder().encode(probes))
        FileHandle.standardOutput.write(Data("\n".utf8))
        exit(probes.allSatisfy { $0.status == "PASS" } ? 0 : 1)
    }
}
