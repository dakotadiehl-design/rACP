public enum ACPProductionProfileSupport {
    /// Current ACP release binaries may expose Full only. Lightweight remains
    /// a conformance/fixture profile until provider and HIL qualification.
    public static let supported: Set<ACPSecurityProfile> = [.full]

    public static func requireSupported(_ profile: ACPSecurityProfile) throws {
        guard supported.contains(profile) else { throw ACPSecurityAdmissionError.authenticationFailed }
    }
}
