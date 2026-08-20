import Foundation

enum RepoRoot {
    static func url() -> URL {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<8 {
            let candidate = url.appendingPathComponent("vectors/manifest.json")
            if FileManager.default.fileExists(atPath: candidate.path) {
                return url
            }
            url.deleteLastPathComponent()
        }
        preconditionFailure("could not locate repository root from \(#filePath)")
    }
}
