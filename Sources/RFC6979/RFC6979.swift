//
//  RFC6979.swift
//
//  Created by walteh on 12/5/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
//

import Foundation

import CRFC6979

public enum RFC6979 {
	public enum Error: Swift.Error {
		case invalidKey
		case invalidSignature
		case invalidHash
		case invalidCurve
		case invalidStrategy
		case invalidRecID
	}

	public enum SHA3Algorithm: Int32 {
		case Ethereum = 1
		case Standard = 0
	}

	public enum Curve {
		case secp256k1
		var load: uECC_Curve {
			switch self {
			case .secp256k1: return uECC_secp256k1()
			}
		}
	}

	public enum Strategy {
		case EthereumRecoverable
		case EthereumTransaction
		case EthereumMessage

		var hasher: (Data) -> Data {
			switch self {
			case .EthereumRecoverable, .EthereumTransaction: return { message in RFC6979.hash(.Ethereum, 256, message) }
			case .EthereumMessage: return { message in
					RFC6979.hash(.Ethereum, 256, "\u{19}Ethereum Signed Message:\n\(message.count)".data(using: .ascii)! + message)
				}
			}
		}

		var buildRecID: (UInt8) -> UInt8 {
			switch self {
			case .EthereumRecoverable: return { x in x }
			case .EthereumTransaction, .EthereumMessage: return { x in x + 27 }
			}
		}
	}

	public struct Signature {
		public let s: Data
		public let r: Data
		public let v: UInt8

		public func serialize(rlp _: Bool = true) -> Data {
			var res = self.r
			res.append(self.s)
			res.append(Data([self.v]))
			return res
		}
	}

	static func hash(_ algo: SHA3Algorithm, _ bits: Int32, _ data: Data) -> Data {
		let nsData = data as NSData
		let input = nsData.bytes.bindMemory(to: UInt8.self, capacity: data.count)
		let result = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)

		sha3_raw(result, 32, input, data.count, algo.rawValue, bits)

		return Data(bytes: result, count: 32)
	}

	static func signDeterministic(_ curve: RFC6979.Curve, _ strategy: RFC6979.Strategy, message: Data, privateKey: Data) throws -> RFC6979.Signature {
		var sig: UnsafeMutablePointer<UInt8> = .allocate(capacity: 64)

		let rec = UnsafeMutablePointer<Int32>.allocate(capacity: 1)

		rec.pointee = 69

		let digest = strategy.hasher(message)
		let c = digest.withUnsafeBytes { d in
			privateKey.withUnsafeBytes { p in
				sign_rfc6979(p.baseAddress, d.baseAddress, 32, rec, sig, curve.load)
			}
		}
		if c == 0 {
			throw RFC6979.Error.invalidKey
		}

		var r: [UInt8] = []
		for _ in 0 ..< 32 {
			r.append(sig.pointee)
			sig = sig.successor()
		}

		var s: [UInt8] = []
		for _ in 32 ..< 64 {
			s.append(sig.pointee)
			sig = sig.successor()
		}

		return .init(s: Data(s), r: Data(r), v: strategy.buildRecID(UInt8(rec.pointee)))
	}

	static func hexToData(_ dat: String) -> Data? {
		let hexStr = dat.dropFirst(dat.hasPrefix("0x") ? 2 : 0)

		guard hexStr.count % 2 == 0 else { return nil }

		var newData = Data(capacity: hexStr.count / 2)

		var indexIsEven = true
		for i in hexStr.indices {
			if indexIsEven {
				let byteRange = i ... hexStr.index(after: i)
				guard let byte = UInt8(hexStr[byteRange], radix: 16) else { return nil }
				newData.append(byte)
			}
			indexIsEven.toggle()
		}
		return newData
	}

	static func dataToHex(_ dat: Data) -> String {
		return dat.map { String(format: "%02hhx", $0) }.joined()
	}
}
