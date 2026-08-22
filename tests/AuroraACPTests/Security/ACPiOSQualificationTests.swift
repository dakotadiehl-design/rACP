#if os(iOS)
import XCTest
@testable import AuroraACP

final class ACPiOSQualificationTests: XCTestCase {
    func testWebSocketExplicitIPv4LoopbackBinding() async throws {
        let listener = try ACPWebSocketListener(port: 0, loopbackOnly: true)
        try await listener.start()
        let advertisedPort = await listener.port
        let port = try XCTUnwrap(advertisedPort)
        async let accepted = listener.accept(timeout: 5)
        let client = try await ACPWebSocketConnection.connect(host: "127.0.0.1", port: port, timeout: 5)
        let server = try await accepted
        try await client.send(Data("simulator-loopback".utf8), text: true)
        let received = try await server.recv()
        XCTAssertEqual(received.0, Data("simulator-loopback".utf8))
        await client.close()
        await server.close()
        await listener.stop()
    }
}
#endif
