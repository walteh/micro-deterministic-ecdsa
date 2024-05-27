//
//  MicroDeterministicECDSATests.swift
//
//  Created by walteh on 2023-03-03.
//

import Foundation
import XCTest
@testable import MicroDeterministicECDSA

class MainTests: XCTestCase {
	let privateKeyAltHex = "E83385AF76B2B1997326B567461FB73DD9C27EAB9E1E86D26779F4650C5F2B75".lowercased()
	var privateKeyAltData: Data { MicroDeterministicECDSA.hexToData(self.privateKeyAltHex)! }

	var publicKeyAltData: Data { try! MicroDeterministicECDSA.publicKey(.secp256k1, privateKey: self.privateKeyAltData) }
	var publicKeyAltHex: String { MicroDeterministicECDSA.dataToHex(self.publicKeyAltData) }
	var publicKeyAltAddressData: Data { MicroDeterministicECDSA.publicKeyToAddress(self.publicKeyAltData) }
	var publicKeyAltAddressHex: String { MicroDeterministicECDSA.dataToHex(self.publicKeyAltAddressData) }

	let privateKeyHex = "00bb19aec0b23e3b0a221fe5c67cd7fe5ec05f882d7d79235b1a0640d3021a4f".lowercased()
	var privateKeyData: Data { MicroDeterministicECDSA.hexToData(self.privateKeyHex)! }

	var publicKeyData: Data { try! MicroDeterministicECDSA.publicKey(.secp256k1, privateKey: self.privateKeyData) }
	var publicKeyHex: String { MicroDeterministicECDSA.dataToHex(self.publicKeyData) }
	var publicKeyAddressData: Data { MicroDeterministicECDSA.publicKeyToAddress(self.publicKeyData) }
	var publicKeyAddressHex: String { MicroDeterministicECDSA.dataToHex(self.publicKeyAddressData) }

	var privateKeyOpensslPem: String { "-----BEGIN EC PRIVATE KEY-----\n\(self.privateKeyData.base64EncodedString())\n-----END EC PRIVATE KEY-----" }

	let transactionHex = "02e9055821424d9400aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbb88016345785d8a00018461626364c0".lowercased()
	var transactionData: Data { MicroDeterministicECDSA.hexToData(self.transactionHex)! }

	let transactionSignatureHex = "3b25864dc856704db0c837d30ef36c6c649a81b79e6d5543c8ccbc77c7665a96592791387cb503f9548fdc4629fc31ac9f778fc131435f73ff8729519d5717721b".lowercased()
	var transactionSignatureData: Data { MicroDeterministicECDSA.hexToData(self.transactionSignatureHex)! }
	var transactionSignature: MicroDeterministicECDSA.Signature { MicroDeterministicECDSA.Signature.fromSerialized(self.transactionSignatureData) }

	let message = "hello"
	var messageData: Data { self.message.data(using: .utf8)! }

	let messageSignatureHex = "9132d6636365fae74dc42f75f9d8fecadb5501bfea7cc30ca97535668fc473f10611fd476150a39b64d1a7b4cca564d756a76673be3cc64e4dc8cd74238319001b".lowercased()
	var messageSignatureData: Data { MicroDeterministicECDSA.hexToData(self.messageSignatureHex)! }
	var messageSignature: MicroDeterministicECDSA.Signature { MicroDeterministicECDSA.Signature.fromSerialized(self.messageSignatureData) }

	func testPublicKeyComputed() throws {
		let prvHex = "E83385AF76B2B1997326B567461FB73DD9C27EAB9E1E86D26779F4650C5F2B75".lowercased()
		let pubHex = "04369D83469A66920F31E4CF3BD92CB0BC20C6E88CE010DFA43E5F08BC49D11DA87970D4703B3ADBC9A140B4AD03A0797A6DE2D377C80C369FE76A0F45A7A39D3F".lowercased()

		let res = try MicroDeterministicECDSA.publicKey(.secp256k1, privateKey: MicroDeterministicECDSA.hexToData(prvHex)!)

		XCTAssertEqual(MicroDeterministicECDSA.dataToHex(res), pubHex)
	}

	func testPublicKey() throws {
		XCTAssertEqual(self.publicKeyAddressHex, "abA79210c75E82Daeb2753CA82a7A41f3db05D78".lowercased())
	}

	func testSignEthereumMessage() throws {
		let res = try MicroDeterministicECDSA.sign(.secp256k1, .EthereumMessage, message: self.messageData, privateKey: self.privateKeyData)

		let serialized = res.serialize()

		let serializedHex = MicroDeterministicECDSA.dataToHex(serialized)

		XCTAssertEqual(res.r, self.messageSignature.r)
		XCTAssertEqual(res.s, self.messageSignature.s)
		XCTAssertEqual(res.v, self.messageSignature.v)
		XCTAssertEqual(serialized, self.messageSignatureData)
		XCTAssertEqual(serializedHex, self.messageSignatureHex)
	}

	func testVerifyEthereumMessage() throws {
		let res = try MicroDeterministicECDSA.verify(.secp256k1, .EthereumMessage, message: self.messageData, signature: self.messageSignature, publicKey: self.publicKeyData)

		XCTAssertTrue(res)
	}

	func testSignEthereumTransaction() throws {
		let res = try MicroDeterministicECDSA.sign(.secp256k1, .EthereumTransaction, message: self.transactionData, privateKey: self.privateKeyData)

		let serialized = res.serialize()

		let serializedHex = MicroDeterministicECDSA.dataToHex(serialized)

		XCTAssertEqual(res.r, self.transactionSignature.r)
		XCTAssertEqual(res.s, self.transactionSignature.s)
		XCTAssertEqual(res.v, self.transactionSignature.v)
		XCTAssertEqual(serialized, self.transactionSignatureData)
		XCTAssertEqual(serializedHex, self.transactionSignatureHex)
	}

	func testVerifyEthereumTransaction() throws {
		let res = try MicroDeterministicECDSA.verify(.secp256k1, .EthereumTransaction, message: self.transactionData, signature: self.transactionSignature, publicKey: self.publicKeyData)

		XCTAssertTrue(res)
	}

	func testVerifyEthereumTransactionBad() throws {
		let sig = try MicroDeterministicECDSA.sign(.secp256k1, .EthereumTransaction, message: self.transactionData, privateKey: self.privateKeyAltData)
		let invalid = try MicroDeterministicECDSA.verify(.secp256k1, .EthereumTransaction, message: self.transactionData, signature: sig, publicKey: self.publicKeyData)
		let valid = try MicroDeterministicECDSA.verify(.secp256k1, .EthereumTransaction, message: self.transactionData, signature: sig, publicKey: self.publicKeyAltData)
		XCTAssertFalse(invalid)
		XCTAssertTrue(valid)
	}
}