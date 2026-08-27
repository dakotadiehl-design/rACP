import Foundation
import Testing

@testable import ReasonableACP

@Test func goldenMessagesRoundTrip() throws {
  let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent()
  let text = try String(
    contentsOf: root.appending(path: "vectors/racp-v1/messages.txt"), encoding: .utf8)
  for line in text.split(separator: "\n").map(String.init) {
    #expect(try RACPMessage.parse(line).encoded() == line)
  }
}

@Test func jsonIsStrictAndCanonical() throws {
  #expect(
    try JSONValue.parse(#" { "z": 1, "a": "line\nvalue" } "#).encoded()
      == #"{"a":"line\nvalue","z":1}"#)
  for text in [#"{"a":1,"a":2}"#, "NaN", "9007199254740992", #""\ud800""#] {
    #expect(throws: RACPProtocolError.self) { try JSONValue.parse(text) }
  }
}

@Test func framingIsBoundedAndAcceptsCRLF() throws {
  var decoder = RACPLineDecoder(maximum: 4)
  #expect(try decoder.feed(Data("1234\r\n".utf8)) == ["1234"])
  #expect(throws: RACPProtocolError.self) { try decoder.feed(Data("12345".utf8)) }
  _ = try decoder.feed(Data("discard\n".utf8))
  #expect(try decoder.feed(Data("OK\n".utf8)) == ["OK"])
}

@Test func nullValueIsDistinctFromNoValue() throws {
  #expect(try RACPMessage.parse("CMD 1 cue.go") == .command(Command(requestID: 1, name: "cue.go")))
  #expect(
    try RACPMessage.parse("CMD 1 cue.go null")
      == .command(Command(requestID: 1, name: "cue.go", value: .null, hasValue: true)))
}

@Test func jsonSpacesDoNotWeakenTokenGrammar() throws {
  #expect(
    try RACPMessage.parse(#"CMD 1 cue.go {"label":"Stage  Left",  "level": 1}"#)
      == .command(
        Command(
          requestID: 1,
          name: "cue.go",
          value: .object([
            JSONMember("label", .string("Stage  Left")), JSONMember("level", .integer(1)),
          ]),
          hasValue: true
        )
      ))
  #expect(throws: RACPProtocolError.self) { try RACPMessage.parse("SUB  1 cue.current") }
}

@Test func canonicallyEquivalentObjectKeysRemainScalarDistinct() throws {
  let value = try JSONValue.parse(#"{"é":1,"e\u0301":2}"#)
  #expect(try value.encoded() == #"{"é":2,"é":1}"#)
}

@Test func programmaticJSONRejectsInvalidNumbersAndDuplicateMembers() {
  #expect(throws: RACPProtocolError.self) { try JSONValue.number(.infinity).encoded() }
  #expect(throws: RACPProtocolError.self) { try JSONValue.integer(9_007_199_254_740_992).encoded() }
  #expect(throws: RACPProtocolError.self) {
    try JSONValue.object([JSONMember("a", .integer(1)), JSONMember("a", .integer(2))]).encoded()
  }
}
