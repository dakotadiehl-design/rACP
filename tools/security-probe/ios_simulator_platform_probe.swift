import CryptoKit
import Foundation
import Security

struct Probe: Codable {
    let id: String
    let status: String
    let detail: String
}

func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func keychainProbe() -> Probe {
    let service = "org.aurora.acp.qualification"
    let account = "synthetic-identity-reference"
    let value = Data("credential-id:test-only".utf8)
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
    SecItemDelete(query as CFDictionary)
    var add = query
    add[kSecValueData as String] = value
    add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let addStatus = SecItemAdd(add as CFDictionary, nil)
    guard addStatus == errSecSuccess else {
        return Probe(id: "keychain.functional", status: "FAIL", detail: "generic-password create failed OSStatus=\(addStatus); spawn-only harness lacks an application entitlement context")
    }
    var read = query
    read[kSecReturnData as String] = true
    read[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let readStatus = SecItemCopyMatching(read as CFDictionary, &item)
    let matches = readStatus == errSecSuccess && (item as? Data) == value
    let deleteStatus = SecItemDelete(query as CFDictionary)
    var absent: CFTypeRef?
    let absentStatus = SecItemCopyMatching(read as CFDictionary, &absent)
    let pass = matches && deleteStatus == errSecSuccess && absentStatus == errSecItemNotFound
    return Probe(
        id: "keychain.functional",
        status: pass ? "PASS" : "FAIL",
        detail: "create/retrieve/delete ThisDeviceOnly metadata; no secret bytes emitted"
    )
}

func cryptoKitProbe() -> Probe {
    let key = P256.Signing.PrivateKey()
    let message = Data("ACP iOS Simulator signing probe v1".utf8)
    guard let signature = try? key.signature(for: message) else {
        return Probe(id: "cryptokit.p256", status: "FAIL", detail: "signing failed")
    }
    let wrongKey = P256.Signing.PrivateKey()
    let pass = key.publicKey.isValidSignature(signature, for: message)
        && !wrongKey.publicKey.isValidSignature(signature, for: message)
        && key.publicKey.x963Representation.count == 65
        && signature.derRepresentation.first == 0x30
    return Probe(
        id: "cryptokit.p256",
        status: pass ? "PASS" : "FAIL",
        detail: "generate/sign/verify/wrong-key; 65-byte uncompressed public point and DER signature"
    )
}

func vectorProbe(root: URL) -> Probe {
    do {
        let manifestURL = root.appendingPathComponent("manifest.json")
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: manifestURL)) as! [String: Any]
        guard object["freeze"] as? String == "2.1.1",
              object["normative"] as? Bool == true,
              object["provider_independent"] as? Bool == true,
              let files = object["files_sha256"] as? [String: String],
              files.count == 31 else {
            return Probe(id: "vectors.security", status: "FAIL", detail: "manifest metadata/count mismatch")
        }
        for (path, expected) in files {
            let actual = hex(Data(SHA256.hash(data: try Data(contentsOf: root.appendingPathComponent(path)))))
            guard actual == expected else {
                return Probe(id: "vectors.security", status: "FAIL", detail: "hash mismatch: \(path)")
            }
        }
        let bootstrap = try JSONSerialization.jsonObject(
            with: Data(contentsOf: root.appendingPathComponent("bootstrap/raw128.json"))
        ) as! [String: Any]
        guard let rejections = bootstrap["rejections"] as? [String], rejections.count >= 4 else {
            return Probe(id: "vectors.security", status: "FAIL", detail: "bootstrap negatives absent")
        }
        return Probe(id: "vectors.security", status: "PASS", detail: "17 sets; 31 artifact hashes; Freeze 2.1.1")
    } catch {
        return Probe(id: "vectors.security", status: "FAIL", detail: "vector read/parse failed")
    }
}

guard CommandLine.arguments.count == 2 else {
    FileHandle.standardError.write(Data("usage: ios_simulator_platform_probe VECTOR_ROOT\n".utf8))
    exit(2)
}

let probes = [
    vectorProbe(root: URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)),
    cryptoKitProbe(),
    keychainProbe(),
]
let output = try JSONEncoder().encode(probes)
FileHandle.standardOutput.write(output)
FileHandle.standardOutput.write(Data("\n".utf8))
exit(probes.allSatisfy { $0.status == "PASS" } ? 0 : 1)
