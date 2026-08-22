import CryptoKit
import Security
import XCTest

final class ACPHostedKeychainTests: XCTestCase {
    private let service = "org.aurora.acp.qualificationhost"

    override func tearDown() {
        SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrService: service] as CFDictionary)
        SecItemDelete([kSecClass: kSecClassKey, kSecAttrApplicationTag: Data(service.utf8)] as CFDictionary)
        super.tearDown()
    }

    func testMetadataTransactionAndFailures() {
        let base: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
                                     kSecAttrService: service, kSecAttrAccount: "synthetic-reference"]
        SecItemDelete(base as CFDictionary)
        var add = base
        let metadata = Data("credential-id:test-only".utf8)
        add[kSecValueData] = metadata
        add[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        XCTAssertEqual(SecItemAdd(add as CFDictionary, nil), errSecSuccess)
        XCTAssertEqual(SecItemAdd(add as CFDictionary, nil), errSecDuplicateItem)
        var read = base
        read[kSecReturnData] = true
        read[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(read as CFDictionary, &result), errSecSuccess)
        XCTAssertEqual(result as? Data, metadata)
        var wrongGroup = read
        wrongGroup[kSecAttrAccessGroup] = "not.an.entitled.access.group"
        var denied: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(wrongGroup as CFDictionary, &denied), errSecMissingEntitlement)
        XCTAssertEqual(SecItemDelete(base as CFDictionary), errSecSuccess)
        var absent: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(read as CFDictionary, &absent), errSecItemNotFound)
    }

    func testPersistentKeyReferenceSignRetrieveDelete() throws {
        let tag = Data(service.utf8)
        let keyQuery: [CFString: Any] = [kSecClass: kSecClassKey, kSecAttrApplicationTag: tag]
        SecItemDelete(keyQuery as CFDictionary)
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeySizeInBits: 256,
            kSecPrivateKeyAttrs: [kSecAttrIsPermanent: true, kSecAttrApplicationTag: tag,
                                  kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly],
        ]
        var error: Unmanaged<CFError>?
        let privateKey = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
        let digest = Data(SHA256.hash(data: Data("ACP hosted Keychain signing probe v1".utf8)))
        let signature = try XCTUnwrap(
            SecKeyCreateSignature(privateKey, .ecdsaSignatureDigestX962SHA256, digest as CFData, &error)
        ) as Data
        XCTAssertTrue(SecKeyVerifySignature(publicKey, .ecdsaSignatureDigestX962SHA256,
                                            digest as CFData, signature as CFData, &error))
        var storedQuery = keyQuery
        storedQuery[kSecReturnRef] = true
        var stored: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(storedQuery as CFDictionary, &stored), errSecSuccess)
        XCTAssertNotNil(stored)
        XCTAssertEqual(SecItemDelete(keyQuery as CFDictionary), errSecSuccess)
        var absent: CFTypeRef?
        XCTAssertEqual(SecItemCopyMatching(storedQuery as CFDictionary, &absent), errSecItemNotFound)
    }
}
