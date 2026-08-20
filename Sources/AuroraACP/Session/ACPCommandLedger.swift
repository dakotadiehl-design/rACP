import Foundation

public struct ACPCommandRecord: Sendable, Equatable {
    public var commandID: String
    public var idempotencyKey: String?
    public var originNodeID: String
    public var originInstanceID: String
    public var originPrincipal: String?
    public var originSessionID: String?
    public var operation: String
    public var receivedAt: String
    public var disposition: String
    public var result: [String: AnySendable]
    public var resultingEpoch: UInt64?
    public var resultingRevision: UInt64?
    public var expiresAt: String?

    public init(
        commandID: String,
        originNodeID: String,
        originInstanceID: String,
        operation: String,
        disposition: String,
        idempotencyKey: String? = nil,
        originPrincipal: String? = nil,
        originSessionID: String? = nil,
        receivedAt: String = "2026-08-17T16:42:15.231Z",
        result: [String: AnySendable] = [:],
        resultingEpoch: UInt64? = nil,
        resultingRevision: UInt64? = nil,
        expiresAt: String? = nil
    ) {
        self.commandID = commandID
        self.idempotencyKey = idempotencyKey
        self.originNodeID = originNodeID
        self.originInstanceID = originInstanceID
        self.originPrincipal = originPrincipal
        self.originSessionID = originSessionID
        self.operation = operation
        self.receivedAt = receivedAt
        self.disposition = disposition
        self.result = result
        self.resultingEpoch = resultingEpoch
        self.resultingRevision = resultingRevision
        self.expiresAt = expiresAt
    }

    public func reportPayload() -> [String: AnySendable] {
        var payload: [String: AnySendable] = [
            "command_id": .string(commandID),
            "origin_node_id": .string(originNodeID),
            "origin_instance_id": .string(originInstanceID),
            "operation": .string(operation),
            "received_at": .string(receivedAt),
            "disposition": .string(disposition),
            "result": .object(result),
        ]
        if let idempotencyKey { payload["idempotency_key"] = .string(idempotencyKey) }
        if let originPrincipal { payload["origin_principal"] = .string(originPrincipal) }
        if let originSessionID { payload["origin_session_id"] = .string(originSessionID) }
        if let resultingEpoch { payload["resulting_epoch"] = .uint(resultingEpoch) }
        if let resultingRevision { payload["resulting_revision"] = .uint(resultingRevision) }
        if let expiresAt { payload["expires_at"] = .string(expiresAt) }
        return payload
    }
}

/// Bounded ledger keyed by origin node + command identity. Session replacement does not drop records.
public actor ACPCommandLedger {
    private var byCommand: [String: ACPCommandRecord] = [:]
    private var byIdempotency: [String: String] = [:]
    private var order: [String] = []
    private let maxRecords: Int

    public init(maxRecords: Int = 1024) {
        self.maxRecords = maxRecords
    }

    public func remember(_ record: ACPCommandRecord) throws -> ACPCommandRecord {
        let key = Self.commandKey(node: record.originNodeID, command: record.commandID)
        if let existing = byCommand[key] {
            if existing.operation != record.operation {
                throw ACPSessionError("conflict", "command_id reused with different operation")
            }
            return existing
        }
        if let idem = record.idempotencyKey {
            let ikey = Self.commandKey(node: record.originNodeID, command: idem)
            if let prior = byIdempotency[ikey], let held = byCommand[prior] {
                if held.operation != record.operation {
                    throw ACPSessionError("conflict", "idempotency key reused with different operation")
                }
                return held
            }
            byIdempotency[ikey] = key
        }
        if order.count >= maxRecords, let old = order.first {
            order.removeFirst()
            if let dropped = byCommand.removeValue(forKey: old), let idem = dropped.idempotencyKey {
                byIdempotency.removeValue(forKey: Self.commandKey(node: dropped.originNodeID, command: idem))
            }
        }
        byCommand[key] = record
        order.append(key)
        return record
    }

    public func lookup(
        originNodeID: String,
        commandID: String? = nil,
        idempotencyKey: String? = nil,
        originPrincipal: String? = nil,
        originInstanceID: String? = nil
    ) -> ACPCommandRecord? {
        let rec: ACPCommandRecord?
        if let commandID {
            rec = byCommand[Self.commandKey(node: originNodeID, command: commandID)]
        } else if let idempotencyKey, let mapped = byIdempotency[Self.commandKey(node: originNodeID, command: idempotencyKey)] {
            rec = byCommand[mapped]
        } else {
            rec = nil
        }
        guard let rec else { return nil }
        if let originPrincipal, rec.originPrincipal != nil, rec.originPrincipal != originPrincipal {
            return nil
        }
        if let originInstanceID, rec.originInstanceID != originInstanceID {
            return nil
        }
        return rec
    }

    private static func commandKey(node: String, command: String) -> String {
        "\(node.lowercased())|\(command.lowercased())"
    }
}
