//
//  SHA2Tests.swift
//  Tests macOS
//
//  Created by Karl-Johan Alm on 2022-10-25.
//

import XCTest
@testable import WebcashWallet

let tv448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
let tv896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"

let shaOfNil = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
let shaOfabc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
let shaOfTV448 = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
let shaOfTV896 = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
let shaOf1Ma /* 1,000,000 "a"s */ = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"

class SHA2Tests: XCTestCase {

    func testSHA2Hash() throws {
        let hexString = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        let hashData = Data(fromHexEncodedString: hexString)!
        let sha2hash = SHA2Hash(data: hashData)
        XCTAssertNotNil(sha2hash)
        let returnedData = sha2hash.data
        XCTAssertNotNil(returnedData)
        let returnedHexString = returnedData.hexString
        XCTAssertEqual(returnedHexString, hexString)
    }

    func testSHA2Algo() throws {
        // test nil type
        let result = SHA2Context().done().hexString
        XCTAssertEqual(result, shaOfNil)

        // test all types
        for (input, output) in zip(["", "abc", tv448, tv896, String(repeating: "a", count: 1000000)], [shaOfNil, shaOfabc, shaOfTV448, shaOfTV896, shaOf1Ma]) {
            let ctx = SHA2Context()
            ctx.update(data: input.data(using: .utf8)!)
            let result = ctx.done().hexString
            XCTAssertEqual(result, output)
        }
    }

    func testSHA2Readiness() throws {
        let ctx = SHA2Context()
        XCTAssertTrue(ctx.ready)
        _ = ctx.done().hexString
        XCTAssertFalse(ctx.ready)
        ctx.reinitialize()
        XCTAssertTrue(ctx.ready)
    }

    func testSHA2Reinit() throws {
        let ctx = SHA2Context()
        // test all types
        for (input, output) in zip(["", "abc", tv448, tv896, String(repeating: "a", count: 1000000)], [shaOfNil, shaOfabc, shaOfTV448, shaOfTV896, shaOf1Ma]) {
            ctx.update(data: input.data(using: .utf8)!)
            let result = ctx.done().hexString
            XCTAssertEqual(result, output)
            ctx.reinitialize()
        }
    }
}
