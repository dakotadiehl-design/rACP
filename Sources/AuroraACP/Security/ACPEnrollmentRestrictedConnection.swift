import Foundation

package enum ACPEnrollmentRestrictedError: String, Error, Sendable, Equatable {
    case invalidConfiguration = "security.enrollment.invalid_configuration"
    case messageNotAllowed = "security.enrollment.message_not_allowed"
    case invalidEnvelope = "security.enrollment.invalid_envelope"
    case invalidSequence = "security.enrollment.invalid_sequence"
    case resourceLimit = "security.enrollment.resource_limit"
    case timeout = "security.enrollment.timeout"
    case closed = "security.enrollment.closed"
}

package struct ACPEnrollmentRestrictedAction: Sendable {
    package let response: ACPEnvelope?
    package let terminal: Bool
    package let didSend: (@Sendable () async throws -> Void)?

    package init(response: ACPEnvelope? = nil, terminal: Bool = false,
                 didSend: (@Sendable () async throws -> Void)? = nil) {
        self.response = response
        self.terminal = terminal
        self.didSend = didSend
    }
}

/// Package-owned pre-session connection. It admits only the frozen enrollment
/// vocabulary, never constructs a principal, and closes on every error or
/// terminal result.
package actor ACPEnrollmentRestrictedConnection {
    package static let frozenTypes: Set<String> = [
        "security.enrollment.status",
        "security.enrollment.begin",
        "security.enrollment.challenge",
        "security.enrollment.response",
        "security.enrollment.confirm",
        "security.enrollment.approval",
        "security.enrollment.install_result",
        "security.enrollment.cancel",
        "error.report",
    ]

    private let transport: any ACPTransport
    private let localNodeID: ACPSecurityNodeID
    private let allowedInboundTypes: Set<String>
    private let orderedInboundTypes: [String]?
    private let maximumMessages: Int
    private let maximumMessageBytes: Int
    private let timeoutNanoseconds: UInt64
    private var messageCount = 0
    private var closed = false

    package init(
        transport: any ACPTransport,
        localNodeID: ACPSecurityNodeID,
        allowedInboundTypes: Set<String> = frozenTypes,
        orderedInboundTypes: [String]? = nil,
        maximumMessages: Int = 16,
        maximumMessageBytes: Int = 64 * 1024,
        timeoutNanoseconds: UInt64 = 60_000_000_000
    ) throws {
        guard !allowedInboundTypes.isEmpty,
              allowedInboundTypes.isSubset(of: Self.frozenTypes),
              orderedInboundTypes.map({ !$0.isEmpty
                  && Set($0).isSubset(of: allowedInboundTypes) }) ?? true,
              (1...64).contains(maximumMessages),
              (1024...262_144).contains(maximumMessageBytes),
              timeoutNanoseconds > 0 else {
            throw ACPEnrollmentRestrictedError.invalidConfiguration
        }
        self.transport = transport
        self.localNodeID = localNodeID
        self.allowedInboundTypes = allowedInboundTypes
        self.orderedInboundTypes = orderedInboundTypes
        self.maximumMessages = maximumMessages
        self.maximumMessageBytes = maximumMessageBytes
        self.timeoutNanoseconds = timeoutNanoseconds
    }

    package func run(
        handler: @escaping @Sendable (ACPEnvelope) async throws
            -> ACPEnrollmentRestrictedAction
    ) async throws {
        guard !closed else { throw ACPEnrollmentRestrictedError.closed }
        do {
            try await runLoop(handler: handler)
            closed = true
            await transport.close()
        } catch {
            closed = true
            await transport.close()
            throw error
        }
    }

    package func close() async {
        guard !closed else { return }
        closed = true
        await transport.close()
    }

    package func run(
        initial: ACPEnvelope, text: Bool = false,
        handler: @escaping @Sendable (ACPEnvelope) async throws
            -> ACPEnrollmentRestrictedAction
    ) async throws {
        guard !closed else { throw ACPEnrollmentRestrictedError.closed }
        do {
            try admitInitial(initial)
            let encoded = text
                ? try ACPEncoding.encodeJSON(initial)
                : try ACPEncoding.encodeCBOR(initial)
            guard encoded.count <= maximumMessageBytes else {
                throw ACPEnrollmentRestrictedError.resourceLimit
            }
            try await transport.send(encoded, text: text)
            try await runLoop(handler: handler)
            closed = true
            await transport.close()
        } catch {
            closed = true
            await transport.close()
            throw error
        }
    }

    private func runLoop(
        handler: @escaping @Sendable (ACPEnvelope) async throws
            -> ACPEnrollmentRestrictedAction
    ) async throws {
        while messageCount < maximumMessages {
            let (data, text) = try await receiveWithTimeout()
            guard data.count <= maximumMessageBytes else {
                throw ACPEnrollmentRestrictedError.resourceLimit
            }
            let envelope: ACPEnvelope
            do {
                envelope = text
                    ? try ACPEncoding.decodeJSON(data)
                    : try ACPEncoding.decodeCBOR(data)
            } catch {
                throw ACPEnrollmentRestrictedError.invalidEnvelope
            }
            try admit(envelope)
            messageCount += 1
            let action = try await handler(envelope)
            if let response = action.response {
                try admitOutbound(response, request: envelope)
                let encoded = text
                    ? try ACPEncoding.encodeJSON(response)
                    : try ACPEncoding.encodeCBOR(response)
                guard encoded.count <= maximumMessageBytes else {
                    throw ACPEnrollmentRestrictedError.resourceLimit
                }
                try await transport.send(encoded, text: text)
                try await action.didSend?()
            } else if action.didSend != nil {
                throw ACPEnrollmentRestrictedError.invalidSequence
            }
            if action.terminal || Self.terminalTypes.contains(envelope.type) { return }
        }
        throw ACPEnrollmentRestrictedError.resourceLimit
    }

    private func admit(_ envelope: ACPEnvelope) throws {
        guard envelope.acp == ACPModel.protocolVersion,
              allowedInboundTypes.contains(envelope.type),
              (Self.interruptionTypes.contains(envelope.type)
                || (orderedInboundTypes.map({ messageCount < $0.count
                    && $0[messageCount] == envelope.type }) ?? true)),
              envelope.sessionID == nil, envelope.sequence == nil,
              envelope.destination?.nodeID == nil
                || envelope.destination?.nodeID == localNodeID.rawValue,
              envelope.flags.isEmpty,
              let row = ACPRegistry.lookup(envelope.type), row.legalBeforeHandshake,
              (envelope.type == "error.report"
                || (row.legalSessionStates.contains("EnrollmentRestricted")
                    && row.requiredCapability == "security.enrollment")),
              row.qosAllowed.contains(envelope.qos.rawValue) else {
            throw ACPEnrollmentRestrictedError.messageNotAllowed
        }
    }

    private func admitOutbound(_ response: ACPEnvelope, request: ACPEnvelope) throws {
        guard Self.frozenTypes.contains(response.type),
              response.acp == ACPModel.protocolVersion,
              response.sessionID == nil, response.sequence == nil,
              response.source.nodeID == localNodeID.rawValue,
              response.flags.isEmpty,
              response.correlationID == request.messageID,
              let row = ACPRegistry.lookup(response.type), row.legalBeforeHandshake,
              response.type == "error.report"
                || row.legalSessionStates.contains("EnrollmentRestricted") else {
            throw ACPEnrollmentRestrictedError.invalidSequence
        }
        if let expected = ACPRegistry.responseType(for: request.type),
           response.type != expected, response.type != "error.report",
           response.type != "security.enrollment.cancel" {
            throw ACPEnrollmentRestrictedError.invalidSequence
        }
    }

    private func admitInitial(_ envelope: ACPEnvelope) throws {
        guard envelope.type == "security.enrollment.begin",
              envelope.acp == ACPModel.protocolVersion,
              envelope.sessionID == nil, envelope.sequence == nil,
              envelope.source.nodeID == localNodeID.rawValue,
              envelope.destination?.nodeID != nil,
              envelope.correlationID == nil, envelope.flags.isEmpty,
              let row = ACPRegistry.lookup(envelope.type), row.legalBeforeHandshake,
              row.legalSessionStates.contains("EnrollmentRestricted"),
              row.requiredCapability == "security.enrollment",
              row.qosAllowed.contains(envelope.qos.rawValue) else {
            throw ACPEnrollmentRestrictedError.invalidSequence
        }
    }

    private func receiveWithTimeout() async throws -> (Data, Bool) {
        try await withThrowingTaskGroup(of: RestrictedFrame.self) { group in
            group.addTask {
                let value = try await self.transport.recv()
                return RestrictedFrame(data: value.0, text: value.1)
            }
            group.addTask {
                try await Task.sleep(nanoseconds: self.timeoutNanoseconds)
                throw ACPEnrollmentRestrictedError.timeout
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else {
                throw ACPEnrollmentRestrictedError.closed
            }
            return (first.data, first.text)
        }
    }

    private static let terminalTypes: Set<String> = [
        "security.enrollment.install_result",
        "security.enrollment.cancel",
        "error.report",
    ]
    private static let interruptionTypes: Set<String> = [
        "security.enrollment.cancel",
        "error.report",
    ]
}

private struct RestrictedFrame: Sendable {
    let data: Data
    let text: Bool
}
