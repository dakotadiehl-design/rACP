import AuroraACP
import Foundation

private let ACP_SPAKE2_SUCCESS: Int32 = 0
private let ACP_SPAKE2_INVALID_ARGUMENT: Int32 = 1
private let ACP_SPAKE2_RANDOM_FAILED: Int32 = 6
private let ACP_SPAKE2_INTERNAL_FAILED: Int32 = 7
private let ACP_SPAKE2_PROVER_SECRET_BYTES = 64
private let ACP_SPAKE2_SHARE_BYTES = 65
private let ACP_SPAKE2_REGISTRATION_RECORD_BYTES = 97
private let ACP_SPAKE2_VERIFIER_RESPONSE_BYTES = 97
private let ACP_SPAKE2_CONFIRMATION_BYTES = 32
private let ACP_SPAKE2_SHARED_SECRET_BYTES = 32
private let ACP_SPAKE2_MAX_IDENTITY_BYTES = 255
private let ACP_SPAKE2_MAX_CONTEXT_BYTES = 4096

@_silgen_name("acp_spake2_create_registration_record")
private func acp_spake2_create_registration_record(
    _ secret: UnsafePointer<UInt8>?, _ secretLength: Int,
    _ record: UnsafeMutablePointer<UInt8>?, _ recordLength: Int
) -> Int32
@_silgen_name("acp_spake2_prover_create")
private func acp_spake2_prover_create(
    _ secret: UnsafePointer<UInt8>?, _ secretLength: Int,
    _ prover: UnsafePointer<UInt8>?, _ proverLength: Int,
    _ verifier: UnsafePointer<UInt8>?, _ verifierLength: Int,
    _ context: UnsafePointer<UInt8>?, _ contextLength: Int,
    _ output: UnsafeMutablePointer<OpaquePointer?>?
) -> Int32
@_silgen_name("acp_spake2_verifier_create")
private func acp_spake2_verifier_create(
    _ record: UnsafePointer<UInt8>?, _ recordLength: Int,
    _ prover: UnsafePointer<UInt8>?, _ proverLength: Int,
    _ verifier: UnsafePointer<UInt8>?, _ verifierLength: Int,
    _ context: UnsafePointer<UInt8>?, _ contextLength: Int,
    _ output: UnsafeMutablePointer<OpaquePointer?>?
) -> Int32
@_silgen_name("acp_spake2_prover_generate_share")
private func acp_spake2_prover_generate_share(
    _ context: OpaquePointer?, _ share: UnsafeMutablePointer<UInt8>?, _ shareLength: Int
) -> Int32
@_silgen_name("acp_spake2_verifier_process_share")
private func acp_spake2_verifier_process_share(
    _ context: OpaquePointer?, _ share: UnsafePointer<UInt8>?, _ shareLength: Int,
    _ response: UnsafeMutablePointer<UInt8>?, _ responseLength: Int
) -> Int32
@_silgen_name("acp_spake2_prover_process_response_and_consume_key")
private func acp_spake2_prover_process_response_and_consume_key(
    _ context: OpaquePointer?, _ response: UnsafePointer<UInt8>?, _ responseLength: Int,
    _ confirmation: UnsafeMutablePointer<UInt8>?, _ confirmationLength: Int,
    _ key: UnsafeMutablePointer<UInt8>?, _ keyLength: Int
) -> Int32
@_silgen_name("acp_spake2_verifier_verify_confirmation_and_consume_key")
private func acp_spake2_verifier_verify_confirmation_and_consume_key(
    _ context: OpaquePointer?, _ confirmation: UnsafePointer<UInt8>?, _ confirmationLength: Int,
    _ key: UnsafeMutablePointer<UInt8>?, _ keyLength: Int
) -> Int32
@_silgen_name("acp_spake2_destroy")
private func acp_spake2_destroy(_ context: UnsafeMutablePointer<OpaquePointer?>?)

public enum ACPAppleSPAKE2PlusRegistration {
    public static func record(proverSecret: ACPSecretBytes) throws -> Data {
        var record = Data(repeating: 0, count: ACP_SPAKE2_REGISTRATION_RECORD_BYTES)
        let status = proverSecret.withUnsafeBytes { secret in
            guard secret.count == ACP_SPAKE2_PROVER_SECRET_BYTES else {
                return ACP_SPAKE2_INVALID_ARGUMENT
            }
            return record.withUnsafeMutableBytes { output in
                acp_spake2_create_registration_record(
                    secret.bindMemory(to: UInt8.self).baseAddress, secret.count,
                    output.bindMemory(to: UInt8.self).baseAddress, output.count
                )
            }
        }
        guard status == ACP_SPAKE2_SUCCESS else {
            record.resetBytes(in: record.indices)
            throw ACPNormalizeSPAKE2Status(status)
        }
        return record
    }
}

public final class ACPAppleSPAKE2PlusProver: @unchecked Sendable {
    private let lock = NSLock()
    private var context: OpaquePointer?
    private var generated = false
    private var terminal = false

    public init(
        proverSecret: ACPSecretBytes,
        proverIdentity: Data,
        verifierIdentity: Data,
        context transcriptContext: Data
    ) throws {
        guard proverIdentity.count <= ACP_SPAKE2_MAX_IDENTITY_BYTES,
              verifierIdentity.count <= ACP_SPAKE2_MAX_IDENTITY_BYTES,
              transcriptContext.count <= ACP_SPAKE2_MAX_CONTEXT_BYTES else {
            throw ACPSecurityErrorCode.authenticationFailed
        }
        var created: OpaquePointer?
        let status = proverSecret.withUnsafeBytes { secret in
            guard secret.count == ACP_SPAKE2_PROVER_SECRET_BYTES else {
                return ACP_SPAKE2_INVALID_ARGUMENT
            }
            return proverIdentity.withUnsafeBytes { prover in
                verifierIdentity.withUnsafeBytes { verifier in
                    transcriptContext.withUnsafeBytes { transcript in
                        acp_spake2_prover_create(
                            secret.bindMemory(to: UInt8.self).baseAddress, secret.count,
                            prover.bindMemory(to: UInt8.self).baseAddress, prover.count,
                            verifier.bindMemory(to: UInt8.self).baseAddress, verifier.count,
                            transcript.bindMemory(to: UInt8.self).baseAddress, transcript.count,
                            &created
                        )
                    }
                }
            }
        }
        guard status == ACP_SPAKE2_SUCCESS, created != nil else {
            throw ACPNormalizeSPAKE2Status(status)
        }
        context = created
    }

    deinit { destroy() }

    public func generateShare() throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard !generated, !terminal, let context else {
            failLocked(); throw ACPSecurityErrorCode.authenticationFailed
        }
        var share = Data(repeating: 0, count: ACP_SPAKE2_SHARE_BYTES)
        let status = share.withUnsafeMutableBytes {
            acp_spake2_prover_generate_share(
                context, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
        }
        guard status == ACP_SPAKE2_SUCCESS else {
            share.resetBytes(in: share.indices)
            failLocked(); throw ACPNormalizeSPAKE2Status(status)
        }
        generated = true
        return share
    }

    public func processResponseAndConsumeKey(
        _ response: Data
    ) throws -> (confirmation: Data, key: ACPConfirmedSPAKE2PlusKey) {
        lock.lock(); defer { lock.unlock() }
        guard generated, !terminal, response.count == ACP_SPAKE2_VERIFIER_RESPONSE_BYTES,
              let context else {
            failLocked(); throw ACPSecurityErrorCode.authenticationFailed
        }
        var confirmation = Data(repeating: 0, count: ACP_SPAKE2_CONFIRMATION_BYTES)
        var key = Data(repeating: 0, count: ACP_SPAKE2_SHARED_SECRET_BYTES)
        let status = response.withUnsafeBytes { input in
            confirmation.withUnsafeMutableBytes { confirmationOutput in
                key.withUnsafeMutableBytes { keyOutput in
                    acp_spake2_prover_process_response_and_consume_key(
                        context,
                        input.bindMemory(to: UInt8.self).baseAddress, input.count,
                        confirmationOutput.bindMemory(to: UInt8.self).baseAddress, confirmationOutput.count,
                        keyOutput.bindMemory(to: UInt8.self).baseAddress, keyOutput.count
                    )
                }
            }
        }
        terminal = true
        var doomed = self.context
        acp_spake2_destroy(&doomed)
        self.context = nil
        guard status == ACP_SPAKE2_SUCCESS, let secret = ACPSecretBytes(key) else {
            confirmation.resetBytes(in: confirmation.indices)
            key.resetBytes(in: key.indices)
            throw ACPNormalizeSPAKE2Status(status)
        }
        key.resetBytes(in: key.indices)
        return (confirmation, ACPConfirmedSPAKE2PlusKey(secret: secret))
    }

    private func destroy() { lock.lock(); defer { lock.unlock() }; failLocked() }
    private func failLocked() {
        terminal = true
        var doomed = context
        acp_spake2_destroy(&doomed)
        context = nil
    }
}

/// Apple Full-profile verifier backed by ACP's restricted native provider.
public final class ACPAppleSPAKE2PlusVerifier: ACPSPAKE2PlusOperation, @unchecked Sendable {
    private let lock = NSLock()
    private var context: OpaquePointer?
    private var peerShareProcessed = false
    private var terminal = false

    public init(
        registrationRecord: Data,
        proverIdentity: Data,
        verifierIdentity: Data,
        context transcriptContext: Data
    ) throws {
        guard registrationRecord.count == ACP_SPAKE2_REGISTRATION_RECORD_BYTES,
              proverIdentity.count <= ACP_SPAKE2_MAX_IDENTITY_BYTES,
              verifierIdentity.count <= ACP_SPAKE2_MAX_IDENTITY_BYTES,
              transcriptContext.count <= ACP_SPAKE2_MAX_CONTEXT_BYTES else {
            throw ACPSecurityErrorCode.authenticationFailed
        }
        var created: OpaquePointer?
        let status = registrationRecord.withUnsafeBytes { record in
            proverIdentity.withUnsafeBytes { prover in
                verifierIdentity.withUnsafeBytes { verifier in
                    transcriptContext.withUnsafeBytes { transcript in
                        acp_spake2_verifier_create(
                            record.bindMemory(to: UInt8.self).baseAddress, record.count,
                            prover.bindMemory(to: UInt8.self).baseAddress, prover.count,
                            verifier.bindMemory(to: UInt8.self).baseAddress, verifier.count,
                            transcript.bindMemory(to: UInt8.self).baseAddress, transcript.count,
                            &created
                        )
                    }
                }
            }
        }
        guard status == ACP_SPAKE2_SUCCESS, created != nil else {
            throw ACPNormalizeSPAKE2Status(status)
        }
        context = created
    }

    deinit { destroy() }

    public func receive(peerShare: Data) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        guard !terminal, !peerShareProcessed, peerShare.count == ACP_SPAKE2_SHARE_BYTES,
              let context else {
            failLocked()
            throw ACPSecurityErrorCode.authenticationFailed
        }
        var response = Data(repeating: 0, count: ACP_SPAKE2_VERIFIER_RESPONSE_BYTES)
        let status = peerShare.withUnsafeBytes { share in
            response.withUnsafeMutableBytes { output in
                acp_spake2_verifier_process_share(
                    context,
                    share.bindMemory(to: UInt8.self).baseAddress, share.count,
                    output.bindMemory(to: UInt8.self).baseAddress, output.count
                )
            }
        }
        guard status == ACP_SPAKE2_SUCCESS else {
            response.resetBytes(in: response.indices)
            failLocked()
            throw ACPNormalizeSPAKE2Status(status)
        }
        peerShareProcessed = true
        return response
    }

    public func verifyAndConsumeKey(confirmation: Data) throws -> ACPConfirmedSPAKE2PlusKey {
        lock.lock(); defer { lock.unlock() }
        guard !terminal, peerShareProcessed,
              confirmation.count == ACP_SPAKE2_CONFIRMATION_BYTES, let context else {
            failLocked()
            throw ACPSecurityErrorCode.authenticationFailed
        }
        var key = Data(repeating: 0, count: ACP_SPAKE2_SHARED_SECRET_BYTES)
        let status = confirmation.withUnsafeBytes { confirmationBytes in
            key.withUnsafeMutableBytes { output in
                acp_spake2_verifier_verify_confirmation_and_consume_key(
                    context,
                    confirmationBytes.bindMemory(to: UInt8.self).baseAddress, confirmationBytes.count,
                    output.bindMemory(to: UInt8.self).baseAddress, output.count
                )
            }
        }
        terminal = true
        var doomed = self.context
        acp_spake2_destroy(&doomed)
        self.context = nil
        guard status == ACP_SPAKE2_SUCCESS, let secret = ACPSecretBytes(key) else {
            key.resetBytes(in: key.indices)
            throw ACPNormalizeSPAKE2Status(status)
        }
        key.resetBytes(in: key.indices)
        return ACPConfirmedSPAKE2PlusKey(secret: secret)
    }

    private func destroy() {
        lock.lock(); defer { lock.unlock() }
        failLocked()
    }

    private func failLocked() {
        terminal = true
        var doomed = context
        acp_spake2_destroy(&doomed)
        context = nil
    }

}

private func ACPNormalizeSPAKE2Status(_ status: Int32) -> ACPSecurityErrorCode {
    switch status {
    case ACP_SPAKE2_RANDOM_FAILED, ACP_SPAKE2_INTERNAL_FAILED:
        return .resourceLimit
    default:
        return .authenticationFailed
    }
}
