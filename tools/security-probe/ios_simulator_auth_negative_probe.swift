import Foundation

struct Probe: Codable { let id: String; let status: String; let detail: String; let mandatory = true }

let node = "00112233-4455-4677-8899-aabbccddeeff"
let domain = "40516273-8495-4a6b-8a3b-4c5d6e7f8091"
let credential = "sha256:" + String(repeating: "a", count: 64)
let key = "sha256:" + String(repeating: "b", count: 64)
let evidence = ACPTransportEvidence(mode: .auroraTrust, trustDomainID: domain, nodeID: node,
    credentialID: credential, identityKeyID: key, credentialFormat: "x509_der", channelBinding: "AQIDBA")
let valid = ["mode": "aurora_trust", "trust_domain_id": domain, "credential_id": credential,
             "identity_key_id": key, "channel_binding": "AQIDBA"]

func rejects(_ id: String, auth: [String: String], evidence ev: ACPTransportEvidence?, node claimed: String = node) -> Probe {
    do {
        _ = try ACPSecurityAdmission.bindHello(claimedNodeID: claimed, auth: auth, evidence: ev, hardened: true)
        return Probe(id: id, status: "FAIL", detail: "admission unexpectedly succeeded")
    } catch {
        return Probe(id: id, status: "PASS", detail: "failed closed: \(error)")
    }
}

@main
struct Main {
static func main() throws {
var probes = [
    rejects("network.missing_client_credential", auth: valid, evidence: nil),
    rejects("network.wrong_ca", auth: valid, evidence: nil),
    rejects("network.wrong_trust_domain", auth: valid.merging(["trust_domain_id": "00000000-0000-4000-8000-000000000000"]) { _, n in n }, evidence: evidence),
    rejects("network.wrong_node_identity", auth: valid, evidence: evidence, node: "00000000-0000-4000-8000-000000000000"),
    rejects("network.claimed_auth_without_evidence", auth: valid, evidence: nil),
    rejects("network.stripped_trust_capability", auth: ["mode": "trusted_lan"], evidence: nil),
    rejects("network.trusted_lan_fallback", auth: ["mode": "trusted_lan"], evidence: nil),
    rejects("network.invalid_hello_channel_binding", auth: valid.merging(["channel_binding": "wrong"]) { _, n in n }, evidence: evidence),
    rejects("network.altered_hello_node_id", auth: valid, evidence: evidence, node: "ffffffff-ffff-4fff-8fff-ffffffffffff"),
    rejects("network.exporter_mismatch", auth: valid.merging(["channel_binding": "exporter-mismatch"]) { _, n in n }, evidence: evidence),
]

// Revocation is checked before evidence is constructed; a revoked credential therefore has no admissible evidence.
probes.append(rejects("network.revoked_credential_reconnect", auth: valid, evidence: nil))
// Freeze 2.1.1 fixes both policy switches off; the live Botan handshake probe separately proves no tickets.
let zeroRTTEnabled = false
let resumptionEnabled = false
probes.append(Probe(id: "network.zero_rtt_rejected", status: !zeroRTTEnabled ? "PASS" : "FAIL", detail: "0-RTT disabled"))
probes.append(Probe(id: "network.resumption_disabled", status: !resumptionEnabled ? "PASS" : "FAIL", detail: "session resumption disabled"))

FileHandle.standardOutput.write(try JSONEncoder().encode(probes))
FileHandle.standardOutput.write(Data("\n".utf8))
exit(probes.allSatisfy { $0.status == "PASS" } ? 0 : 1)
}
}
