import Foundation

public enum ACPSecurityCatalog {
    private static let document: [String: Any] = {
        let urls = [
            Bundle.module.url(forResource: "constants", withExtension: "json"),
            Bundle.module.url(forResource: "constants", withExtension: "json", subdirectory: "Security"),
            URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("constants.json"),
        ]
        for url in urls.compactMap({ $0 }) {
            if let data = try? Data(contentsOf: url),
               let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] { return value }
        }
        return [:]
    }()

    public static var security: [String: Any] { document["security"] as? [String: Any] ?? [:] }
    public static var capabilities: [String: String] { security["capabilities"] as? [String: String] ?? [:] }
    public static var errors: [String: [String: Any]] { security["errors"] as? [String: [String: Any]] ?? [:] }
    public static func limits(profile: String) -> [String: Any] {
        ((security["limits"] as? [String: Any])?[profile] as? [String: Any]) ?? [:]
    }
    public static func binaryFields(messageType: String) -> [String] {
        ((security["binary_fields"] as? [String: Any])?[messageType] as? [String]) ?? []
    }
}
