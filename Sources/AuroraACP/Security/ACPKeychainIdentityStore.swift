#if canImport(Security)
import Foundation
import Security

public final class ACPKeychainCredentialBackend: ACPCredentialSlotBackend, @unchecked Sendable {
    private let service: String
    private let accessGroup: String?
    public init(service: String = "com.aurora.acp.identity", accessGroup: String? = nil) {
        self.service = service; self.accessGroup = accessGroup
    }
    public func read(name: String) throws -> Data? {
        var query = base(name)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw ACPSecurityErrorCode.storageFailed }
        return data
    }
    public func write(name: String, data: Data) throws {
        let query = base(name)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let update = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if update == errSecItemNotFound {
            var insertion = query; attributes.forEach { insertion[$0] = $1 }
            let add = SecItemAdd(insertion as CFDictionary, nil)
            if add == errSecDuplicateItem {
                guard SecItemUpdate(query as CFDictionary, attributes as CFDictionary) == errSecSuccess
                else { throw ACPSecurityErrorCode.storageFailed }
            } else if add != errSecSuccess { throw ACPSecurityErrorCode.storageFailed }
        } else if update != errSecSuccess { throw ACPSecurityErrorCode.storageFailed }
    }
    /// Atomically creates a value without replacing an existing reservation.
    /// Returns false when another process already owns the exact service/name.
    public func createIfAbsent(name: String, data: Data) throws -> Bool {
        var insertion = base(name)
        insertion[kSecValueData as String] = data
        insertion[kSecAttrAccessible as String]
            = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(insertion as CFDictionary, nil)
        if status == errSecDuplicateItem { return false }
        guard status == errSecSuccess else { throw ACPSecurityErrorCode.storageFailed }
        return true
    }
    public func delete(name: String) throws {
        let status = SecItemDelete(base(name) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw ACPSecurityErrorCode.storageFailed }
    }
    private func base(_ name: String) -> [String: Any] {
        var value: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: name,
        ]
        if let accessGroup { value[kSecAttrAccessGroup as String] = accessGroup }
        return value
    }
}
#endif
