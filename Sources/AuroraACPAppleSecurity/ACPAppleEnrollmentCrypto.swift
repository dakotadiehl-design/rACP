import AuroraACP
import CryptoKit
import Foundation

package struct ACPAppleAESGCM: ACPAEADProvider {
    package init() {}

    package func seal(key: ACPSecretBytes, plaintext: ACPSecretBytes, nonce: Data,
                      associatedData: Data) throws -> Data {
        guard nonce.count == 12 else { throw ACPSecurityErrorCode.resourceLimit }
        do {
            return try key.withUnsafeBytes { keyBytes in
                try plaintext.withUnsafeBytes { plaintextBytes in
                    let box = try AES.GCM.seal(
                        Data(plaintextBytes), using: SymmetricKey(data: Data(keyBytes)),
                        nonce: try AES.GCM.Nonce(data: nonce),
                        authenticating: associatedData)
                    return box.ciphertext + box.tag
                }
            }
        } catch { throw ACPSecurityErrorCode.authenticationFailed }
    }

    package func open(key: ACPSecretBytes, ciphertext: Data, nonce: Data,
                      associatedData: Data) throws -> ACPSecretBytes {
        guard nonce.count == 12, ciphertext.count > 16 else {
            throw ACPSecurityErrorCode.authenticationFailed
        }
        do {
            let plaintext = try key.withUnsafeBytes { keyBytes in
                try AES.GCM.open(AES.GCM.SealedBox(
                    nonce: try AES.GCM.Nonce(data: nonce),
                    ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16)),
                    using: SymmetricKey(data: Data(keyBytes)),
                    authenticating: associatedData)
            }
            guard let secret = ACPSecretBytes(plaintext, label: "approval plaintext") else {
                throw ACPSecurityErrorCode.authenticationFailed
            }
            return secret
        } catch { throw ACPSecurityErrorCode.authenticationFailed }
    }
}
