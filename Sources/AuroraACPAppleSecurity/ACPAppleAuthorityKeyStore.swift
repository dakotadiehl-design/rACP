import AuroraACP
import Foundation
import Security

package enum ACPAppleSecureEnclaveOutcome: Error, Sendable, Equatable {
    case unsupportedPlatform
    case unsupportedRequiredOperation
    case accessDenied
    case storageLocked
    case corruptState
    case identityMismatch
    case duplicateState
    case entitlementFailure
    case providerIntegrityFailure
    case unexpected(OSStatus)

    package var permitsKeychainFallback: Bool {
        self == .unsupportedPlatform || self == .unsupportedRequiredOperation
    }
}

package struct ACPAppleAuthorityKeyRecord: Codable, Sendable, Equatable {
    package static let currentSchemaVersion = 1
    package let schemaVersion: Int
    package let keyID: String
    package let expectedCustody: ACPAppleSigningKeyCustody
    package let expectedSPKIID: String
    package let domainCorrelationID: String?

    package init(key: ACPAppleProtectedSigningKey, domainCorrelationID: String?) {
        schemaVersion = Self.currentSchemaVersion
        keyID = key.keyID.rawValue
        expectedCustody = key.custody
        expectedSPKIID = key.keyID.rawValue
        self.domainCorrelationID = domainCorrelationID
    }
}

/// Creates or reloads the authority key using the frozen Apple v1 custody
/// order. Persisted records contain correlation metadata only; the live SecKey
/// is independently revalidated on every call.
package final class ACPAppleAuthorityKeyStore: @unchecked Sendable {
    private static let creationLock = NSLock()
    private let applicationTag: Data
    private let accessGroup: String?
    private let metadata: ACPKeychainCredentialBackend
    private let metadataAccount: String

    package init(
        applicationTag: Data,
        metadataService: String = "com.aurora.acp.authority-key",
        metadataAccount: String = "authority-key-record",
        accessGroup: String? = nil
    ) throws {
        guard !applicationTag.isEmpty, applicationTag.count <= 128,
              !metadataAccount.isEmpty, metadataAccount.utf8.count <= 128
        else { throw ACPSecurityErrorCode.resourceLimit }
        self.applicationTag = applicationTag
        self.accessGroup = accessGroup
        self.metadata = ACPKeychainCredentialBackend(
            service: metadataService, accessGroup: accessGroup)
        self.metadataAccount = metadataAccount
    }

    package func openOrCreate(domainCorrelationID: String? = nil) throws -> ACPAppleProtectedSigningKey {
        Self.creationLock.lock(); defer { Self.creationLock.unlock() }
        return try openOrCreateLocked(domainCorrelationID: domainCorrelationID)
    }

    /// Reopens an authority key after anchor generation. This path never
    /// creates a replacement: missing or mismatched custody fails closed.
    package func openExisting(
        domainCorrelationID: String, expectedKeyID: ACPIdentityKeyID,
        expectedCustody: ACPAppleSigningKeyCustody
    ) throws -> ACPAppleProtectedSigningKey {
        Self.creationLock.lock(); defer { Self.creationLock.unlock() }
        if try metadata.read(name: metadataAccount) != nil {
            let loaded = try openOrCreateLocked(
                domainCorrelationID: domainCorrelationID)
            guard loaded.keyID == expectedKeyID, loaded.custody == expectedCustody else {
                throw ACPAppleSecureEnclaveOutcome.identityMismatch
            }
            return loaded
        }
        let keys = try findKeys()
        guard keys.count == 1, let key = keys.first else {
            throw keys.isEmpty ? ACPAppleSecurityError.privateKeyUnavailable
                : ACPAppleSecureEnclaveOutcome.duplicateState
        }
        let capability = try ACPAppleProtectedSigningKey(
            secKey: key, expectedKeyID: expectedKeyID,
            expectedCustody: expectedCustody)
        try capability.proveOperational()
        let record = ACPAppleAuthorityKeyRecord(
            key: capability, domainCorrelationID: domainCorrelationID)
        try metadata.write(
            name: metadataAccount, data: try JSONEncoder().encode(record))
        return capability
    }

    private func openOrCreateLocked(
        domainCorrelationID: String?
    ) throws -> ACPAppleProtectedSigningKey {
        if let encoded = try metadata.read(name: metadataAccount) {
            let record: ACPAppleAuthorityKeyRecord
            guard encoded.count <= 4096 else {
                throw ACPAppleSecureEnclaveOutcome.corruptState
            }
            do { record = try JSONDecoder().decode(ACPAppleAuthorityKeyRecord.self, from: encoded) }
            catch { throw ACPAppleSecureEnclaveOutcome.corruptState }
            guard record.schemaVersion == ACPAppleAuthorityKeyRecord.currentSchemaVersion,
                  record.domainCorrelationID == domainCorrelationID,
                  let expected = ACPIdentityKeyID(rawValue: record.keyID),
                  record.expectedSPKIID == record.keyID
            else { throw ACPAppleSecureEnclaveOutcome.identityMismatch }
            let key = try loadUniqueKey()
            let capability = try ACPAppleProtectedSigningKey(
                secKey: key, expectedKeyID: expected, expectedCustody: record.expectedCustody)
            try capability.proveOperational()
            return capability
        }

        let orphanedKeys = try findKeys()
        if !orphanedKeys.isEmpty {
            // A unique key may be adopted only while an authority bootstrap has
            // already reserved and supplied its domain correlation ID. This
            // recovers a crash between SecKey creation and metadata commit.
            guard domainCorrelationID != nil, orphanedKeys.count == 1,
                  let orphan = orphanedKeys.first else {
                throw ACPAppleSecureEnclaveOutcome.duplicateState
            }
            let capability = try ACPAppleProtectedSigningKey(secKey: orphan)
            try capability.proveOperational()
            let record = ACPAppleAuthorityKeyRecord(
                key: capability, domainCorrelationID: domainCorrelationID)
            try metadata.write(name: metadataAccount, data: try JSONEncoder().encode(record))
            return capability
        }
        let key = try Self.selectCustody(
            secureEnclave: { try self.createKey(secureEnclave: true) },
            keychain: { try self.createKey(secureEnclave: false) })
        do {
            let capability = try ACPAppleProtectedSigningKey(secKey: key)
            try capability.proveOperational()
            let record = ACPAppleAuthorityKeyRecord(
                key: capability, domainCorrelationID: domainCorrelationID)
            try metadata.write(name: metadataAccount, data: try JSONEncoder().encode(record))
            return capability
        } catch {
            try? delete(key: key)
            throw error
        }
    }

    /// The fallback decision is centralized here so callers cannot interpret
    /// arbitrary Security.framework errors as permission to weaken custody.
    package static func selectCustody<T>(
        secureEnclave: () throws -> T,
        keychain: () throws -> T
    ) throws -> T {
        do { return try secureEnclave() }
        catch let outcome as ACPAppleSecureEnclaveOutcome {
            guard outcome.permitsKeychainFallback else { throw outcome }
            return try keychain()
        }
    }

    private func createKey(secureEnclave: Bool) throws -> SecKey {
        var privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrIsExtractable as String: false,
            kSecAttrApplicationTag as String: applicationTag,
        ]
        if secureEnclave {
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                .privateKeyUsage, nil) else {
                throw ACPAppleSecureEnclaveOutcome.providerIntegrityFailure
            }
            privateAttributes[kSecAttrAccessControl as String] = access
        } else {
            privateAttributes[kSecAttrAccessible as String]
                = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }
        if let accessGroup { privateAttributes[kSecAttrAccessGroup as String] = accessGroup }
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: privateAttributes,
        ]
        if secureEnclave { attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave }
        var error: Unmanaged<CFError>?
        if let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
            guard SecKeyIsAlgorithmSupported(
                key, .sign, .ecdsaSignatureDigestX962SHA256) else {
                try? delete(key: key)
                if secureEnclave { throw ACPAppleSecureEnclaveOutcome.unsupportedRequiredOperation }
                throw ACPAppleSecurityError.privateKeyUnavailable
            }
            return key
        }
        let retained = error?.takeRetainedValue()
        if secureEnclave { throw Self.classifySecureEnclaveFailure(retained) }
        throw ACPAppleSecurityError.privateKeyUnavailable
    }

    package static func classifySecureEnclaveFailure(_ error: CFError?) -> ACPAppleSecureEnclaveOutcome {
        guard let error else { return .providerIntegrityFailure }
        let code = OSStatus(CFErrorGetCode(error))
        switch code {
        case errSecUnimplemented: return .unsupportedPlatform
        case errSecAuthFailed: return .accessDenied
        case errSecInteractionNotAllowed: return .storageLocked
        case errSecDecode: return .corruptState
        case errSecDuplicateItem: return .duplicateState
        case errSecMissingEntitlement: return .entitlementFailure
        default: return .unexpected(code)
        }
    }

    package func reset() throws {
        Self.creationLock.lock(); defer { Self.creationLock.unlock() }
        for key in try findKeys() { try delete(key: key) }
        try metadata.delete(name: metadataAccount)
    }

    private func findKeys() throws -> [SecKey] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: applicationTag,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw ACPAppleSecurityError.keychainFailure }
        if let keys = result as? [SecKey] { return keys }
        if let result, CFGetTypeID(result) == SecKeyGetTypeID() {
            return [unsafeBitCast(result, to: SecKey.self)]
        }
        throw ACPAppleSecureEnclaveOutcome.corruptState
    }

    private func loadUniqueKey() throws -> SecKey {
        let keys = try findKeys()
        guard keys.count == 1, let key = keys.first else {
            throw keys.isEmpty ? ACPAppleSecurityError.privateKeyUnavailable
                : ACPAppleSecureEnclaveOutcome.duplicateState
        }
        return key
    }

    private func delete(key: SecKey) throws {
        let status = SecItemDelete([
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: key,
        ] as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ACPAppleSecurityError.keychainFailure
        }
    }
}
