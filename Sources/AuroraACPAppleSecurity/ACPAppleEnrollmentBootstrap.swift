import AuroraACP
import CryptoKit
import Foundation

public final class ACPAppleEnrollmentBootstrapSecret: @unchecked Sendable {
    package enum Form { case raw128, manualNumeric }
    package let form: Form
    private let bytes: ACPSecretBytes

    private init(form: Form, bytes: Data) throws {
        guard let secret = ACPSecretBytes(bytes, label: "enrollment bootstrap secret") else {
            throw ACPAppleEnrollmentServiceError.invalidBootstrapSecret
        }
        self.form = form; self.bytes = secret
    }

    public static func highEntropyCode(_ code: String) throws -> Self {
        try .init(form: .raw128, bytes: ACPAppleEnrollmentBootstrap.decodeCrockford(code))
    }

    public static func manualNumericCode(_ code: String) throws -> Self {
        guard (8...12).contains(code.utf8.count),
              code.utf8.allSatisfy({ (0x30...0x39).contains($0) }) else {
            throw ACPAppleEnrollmentServiceError.invalidBootstrapSecret
        }
        return try .init(form: .manualNumeric, bytes: Data(code.utf8))
    }

    package func copyData() -> Data { bytes.withUnsafeBytes { Data($0) } }
    deinit { bytes.clear() }
}

package enum ACPAppleEnrollmentBootstrap {
    package static func registrationRecord(
        secret: ACPAppleEnrollmentBootstrapSecret,
        enrollmentID: ACPEnrollmentID,
        candidateNodeID: ACPSecurityNodeID,
        commissionerNodeID: ACPSecurityNodeID
    ) throws -> (suite: ACPSecuritySuite, record: ACPSecretBytes) {
        let derived = try proverSecret(
            secret: secret, enrollmentID: enrollmentID,
            candidateNodeID: candidateNodeID, commissionerNodeID: commissionerNodeID)
        defer { derived.secret.clear() }
        var recordData = try ACPAppleSPAKE2PlusRegistration.record(
            proverSecret: derived.secret)
        defer { recordData.resetBytes(in: recordData.indices) }
        guard let record = ACPSecretBytes(recordData, label: "SPAKE2+ verifier record") else {
            throw ACPAppleEnrollmentServiceError.invalidBootstrapSecret
        }
        return (derived.suite, record)
    }

    package static func proverSecret(
        secret: ACPAppleEnrollmentBootstrapSecret,
        enrollmentID: ACPEnrollmentID,
        candidateNodeID: ACPSecurityNodeID,
        commissionerNodeID: ACPSecurityNodeID
    ) throws -> (suite: ACPSecuritySuite, secret: ACPSecretBytes) {
        let password: Data
        let suite: ACPSecuritySuite
        switch secret.form {
        case .raw128:
            password = secret.copyData(); suite = .raw128
        case .manualNumeric:
            password = secret.copyData(); suite = .pbkdf2_100K
        }
        var registrationInput = littleEndianLength(password.count) + password
            + littleEndianLength(16) + uuidBytes(candidateNodeID.rawValue)
            + littleEndianLength(16) + uuidBytes(commissionerNodeID.rawValue)
        let saltInput = Data("ACP SPAKE2+ registration salt v1".utf8)
            + littleEndianLength(16) + uuidBytes(enrollmentID.rawValue)
            + littleEndianLength(16) + uuidBytes(candidateNodeID.rawValue)
            + littleEndianLength(16) + uuidBytes(commissionerNodeID.rawValue)
        let salt = Data(SHA256.hash(data: saltInput))
        var expanded: Data
        switch suite {
        case .raw128:
            expanded = Data(HKDF<SHA256>.deriveKey(
                inputKeyMaterial: SymmetricKey(data: registrationInput), salt: salt,
                info: Data("ACP SPAKE2+ RAW128 registration v1".utf8),
                outputByteCount: 80).withUnsafeBytes { Data($0) })
        case .pbkdf2_100K:
            expanded = pbkdf2SHA256(
                password: registrationInput, salt: salt, iterations: 100_000,
                outputCount: 80)
        }
        defer {
            registrationInput.resetBytes(in: registrationInput.indices)
            expanded.resetBytes(in: expanded.indices)
        }
        var scalars = reduceP256(Data(expanded.prefix(40)))
            + reduceP256(Data(expanded.dropFirst(40)))
        defer { scalars.resetBytes(in: scalars.indices) }
        guard let scalarSecret = ACPSecretBytes(scalars, label: "SPAKE2+ scalars") else {
            throw ACPAppleEnrollmentServiceError.invalidBootstrapSecret
        }
        return (suite, scalarSecret)
    }

    package static func decodeCrockford(_ input: String) throws -> Data {
        let normalized = input.uppercased().filter { $0 != "-" && !$0.isWhitespace }
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        guard normalized.count == 26 else {
            throw ACPAppleEnrollmentServiceError.invalidBootstrapSecret
        }
        var bits: [UInt8] = []
        bits.reserveCapacity(130)
        for character in normalized {
            guard let value = alphabet.firstIndex(of: character) else {
                throw ACPAppleEnrollmentServiceError.invalidBootstrapSecret
            }
            for shift in stride(from: 4, through: 0, by: -1) {
                bits.append(UInt8((value >> shift) & 1))
            }
        }
        guard bits[0] == 0, bits[1] == 0 else {
            throw ACPAppleEnrollmentServiceError.invalidBootstrapSecret
        }
        var result = Data(count: 16)
        for index in 0..<128 where bits[index + 2] == 1 {
            result[index / 8] |= UInt8(1 << (7 - index % 8))
        }
        return result
    }

    private static func pbkdf2SHA256(password: Data, salt: Data,
                                     iterations: Int, outputCount: Int) -> Data {
        let key = SymmetricKey(data: password)
        var output = Data()
        var block: UInt32 = 1
        while output.count < outputCount {
            var bigEndian = block.bigEndian
            var input = salt
            withUnsafeBytes(of: &bigEndian) { input.append(contentsOf: $0) }
            var u = Data(HMAC<SHA256>.authenticationCode(for: input, using: key))
            var aggregate = u
            for _ in 1..<iterations {
                u = Data(HMAC<SHA256>.authenticationCode(for: u, using: key))
                for index in aggregate.indices { aggregate[index] ^= u[index] }
            }
            output += aggregate; block += 1
        }
        return Data(output.prefix(outputCount))
    }

    private static func reduceP256(_ input: Data) -> Data {
        let order = Data([
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
        ])
        var remainder = Data()
        for byte in input {
            remainder.append(byte)
            while remainder.count > 1 && remainder.first == 0 { remainder.removeFirst() }
            while compare(remainder, order) >= 0 { remainder = subtract(remainder, order) }
        }
        return Data(repeating: 0, count: max(0, 32 - remainder.count)) + remainder
    }

    private static func compare(_ left: Data, _ right: Data) -> Int {
        if left.count != right.count { return left.count < right.count ? -1 : 1 }
        for (a, b) in zip(left, right) where a != b { return a < b ? -1 : 1 }
        return 0
    }

    private static func subtract(_ left: Data, _ right: Data) -> Data {
        var result = Array(left), rhs = Array(repeating: UInt8(0),
            count: left.count - right.count) + Array(right)
        var borrow = 0
        for index in stride(from: result.count - 1, through: 0, by: -1) {
            var value = Int(result[index]) - Int(rhs[index]) - borrow
            if value < 0 { value += 256; borrow = 1 } else { borrow = 0 }
            result[index] = UInt8(value)
        }
        while result.count > 1 && result.first == 0 { result.removeFirst() }
        _ = rhs.withUnsafeMutableBytes {
            $0.initializeMemory(as: UInt8.self, repeating: 0)
        }
        return Data(result)
    }

    private static func littleEndianLength(_ value: Int) -> Data {
        var number = UInt64(value).littleEndian
        return withUnsafeBytes(of: &number) { Data($0) }
    }
    private static func uuidBytes(_ value: String) -> Data {
        var uuid = UUID(uuidString: value)!.uuid
        return withUnsafeBytes(of: &uuid) { Data($0) }
    }
}
