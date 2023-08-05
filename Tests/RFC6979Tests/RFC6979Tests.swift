//
//  swift_sdkTests.swift
//  swift-sdkTests
//
//  Created by walteh on 3/3/23.
//
import Foundation
import XCTest
@testable import RFC6979

class MainTests: XCTestCase {
	let privateKey = RFC6979.hexToData("00bb19aec0b23e3b0a221fe5c67cd7fe5ec05f882d7d79235b1a0640d3021a4f")!

	func testEthereumTransaction() throws {
		let transaction = RFC6979.hexToData("02e9055821424d9400aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbb88016345785d8a00018461626364c0")!
		let want = "3b25864dc856704db0c837d30ef36c6c649a81b79e6d5543c8ccbc77c7665a96592791387cb503f9548fdc4629fc31ac9f778fc131435f73ff8729519d5717721b"

		let res = try RFC6979.signDeterministic(.secp256k1, .EthereumTransaction, message: transaction, privateKey: self.privateKey)

		let resHex = RFC6979.dataToHex(res.serialize())

		XCTAssertEqual(resHex, want)

		print(RFC6979.dataToHex(res.serialize()))
	}

	func testEthereumMessage() throws {
		let message = "hello"

		let combo = message.data(using: .utf8)!

		let transaction = RFC6979.hexToData("68656c6c6f")!

		XCTAssertEqual(combo, transaction)

		let want = "9132d6636365fae74dc42f75f9d8fecadb5501bfea7cc30ca97535668fc473f10611fd476150a39b64d1a7b4cca564d756a76673be3cc64e4dc8cd74238319001b"

		let res = try RFC6979.signDeterministic(.secp256k1, .EthereumMessage, message: transaction, privateKey: self.privateKey)

		let resHex = RFC6979.dataToHex(res.serialize())

		XCTAssertEqual(resHex, want)

		print(RFC6979.dataToHex(res.serialize()))
	}
}
