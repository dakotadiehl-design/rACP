import AuroraACP
import AuroraACPAppleSecurity
import Foundation

func openHost(manifest: Data) async throws -> ACPAppleHost {
    let identity = ACPIdentity(
        nodeID: "00112233-4455-4677-8899-aabbccddeeff",
        role: "host", name: "External Consumer")
    let configuration = try ACPAppleHostConfiguration(
        identity: identity,
        storageNamespace: "com.aurora.acp.external-consumer",
        providerProvenance: try ACPProviderProvenance(jsonData: manifest))
    let host = try await ACPAppleHostFactory.openOrBootstrap(configuration: configuration)
    _ = host.provisioningStatus
    _ = host.trustedPeers()
    _ = try await host.pendingEnrollmentRequests()
    let enrollment = try host.makeEnrollmentService(
        configuration: try ACPAppleEnrollmentServiceConfiguration())
    let endpoint = try await enrollment.start()
    _ = (endpoint, await enrollment.statusUpdates())
    let candidate = try ACPAppleEnrollmentCandidate(
        enrollmentID: ACPEnrollmentID(rawValue: UUID().uuidString.lowercased())!,
        nodeID: ACPSecurityNodeID(rawValue: UUID().uuidString.lowercased())!,
        displayName: "Candidate", requestedRole: "remote",
        bootstrapSecret: .manualNumericCode("12345678"))
    let enrollmentTask = Task { try await enrollment.beginEnrollment(candidate) }
    enrollmentTask.cancel()
    _ = await host.enrollmentRequestUpdates()
    _ = try host.operationalStatus()
    _ = try host.planLocalSecurityReset()
    await enrollment.shutdown()
    let provider = try host.makeFullProviderConfiguration()
    _ = provider
    _ = try host.makeFullServerListener()
    return host
}

// This target is a compile-only public API fixture. It deliberately belongs to
// a separate Swift package so `package` declarations are inaccessible.
