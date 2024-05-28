//
//  MicroDeterministicECDSA.swift
//
//  Created by walteh on 2022-12-05.
//  Copyright © 2022 Walter Scott. All rights reserved.
//

import CryptoKit
import Foundation

import MicroDeterministicECDSA_Src

public enum Error: Swift.Error {
	case invalidKey
	case invalidSignature
	case invalidHash
	case invalidCurve
	case invalidStrategy
	case invalidRecID
}

public enum HashingAlgorithm: Int32 {
	case Keccak256 = 1
	case SHA3 = 2
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
	case Standard_SHA3_256

	var hasher: (Data) -> Data {
		switch self {
		case .Standard_SHA3_256: return { message in MicroDeterministicECDSA.hash(.SHA3, 256, message) }
		case .EthereumRecoverable, .EthereumTransaction: return { message in MicroDeterministicECDSA.hash(.Keccak256, 256, message) }
		case .EthereumMessage: return { message in
				MicroDeterministicECDSA.hash(.Keccak256, 256, "\u{19}Ethereum Signed Message:\n\(message.count)".data(using: .ascii)! + message)
			}
		}
	}

	var buildRecID: (UInt8) -> UInt8 {
		switch self {
		case
			.Standard_SHA3_256,
			.EthereumRecoverable: return { x in x }
		case .EthereumTransaction,
		     .EthereumMessage:
			return { x in x + 27 }
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

	public static func fromSerialized(_ data: Data) -> Signature {
		let r = data.subdata(in: 0 ..< 32)
		let s = data.subdata(in: 32 ..< 64)
		let v = data.subdata(in: 64 ..< 65).first!
		return Signature(s: s, r: r, v: v)
	}
}

func hash(_ algo: HashingAlgorithm, _ bits: Int32, _ data: Data) -> Data {
	switch algo {
	case .Keccak256:
		let nsData = data as NSData
		let input = nsData.bytes.bindMemory(to: UInt8.self, capacity: data.count)
		let result = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)

		keccak256_raw(result, 32, input, data.count, algo.rawValue, bits)

		return Data(bytes: result, count: 32)
	case .SHA3:
		// do normal hashing
		switch bits {
		case 256:
			return SHA256.hash(data: data).withUnsafeBytes { Data($0) }
		case 512:
			return SHA512.hash(data: data).withUnsafeBytes { Data($0) }
		case 384:
			return SHA384.hash(data: data).withUnsafeBytes { Data($0) }
		default:
			fatalError("Unsupported hash size")
		}
	}
}

func sign(message: Data, privateKey: Data, on: Curve, as strategy: Strategy) throws -> Signature {
	let sig: UnsafeMutablePointer<UInt8> = .allocate(capacity: 64)
	defer { sig.deallocate() }

	let rec: UnsafeMutablePointer<Int32> = .allocate(capacity: 1)
	defer { rec.deallocate() }

	rec.pointee = 70 // some invalid value

	let digest: Data = strategy.hasher(message)
	let c = digest.withUnsafeBytes { d in
		privateKey.withUnsafeBytes { p in
			sign_rfc6979(p.baseAddress, d.baseAddress, 32, rec, sig, on.load)
		}
	}
	if c == 0 {
		throw Error.invalidKey
	}

	let signatureBytes = UnsafeBufferPointer(start: sig, count: 64)

	return .init(
		s: Data(signatureBytes[32 ..< 64]),
		r: Data(signatureBytes[0 ..< 32]),
		v: strategy.buildRecID(UInt8(rec.pointee))
	)
}

func verify(message: Data, signature: Signature, publicKey: Data, on: Curve, as strategy: Strategy = .Standard_SHA3_256) throws -> Bool {
	let digest = strategy.hasher(message)

	let sig = signature.serialize()

	let pub: UnsafeMutableBufferPointer<UInt8> = .allocate(capacity: 64)
	defer { pub.deallocate() }

	if publicKey.count == 65, publicKey[0] == 4 {
		_ = pub.initialize(from: publicKey[1 ..< 65])
	} else {
		_ = pub.initialize(from: publicKey[0 ..< 64])
	}

	let c = digest.withUnsafeBytes { d in
		sig.withUnsafeBytes { s in
			verify_rfc6979(pub.baseAddress, d.baseAddress, 32, s.baseAddress, on.load)
		}
	}

	return c == 1
}

public func publicKeyFrom(privateKey: Data, on: Curve) throws -> Data {
	let pub: UnsafeMutablePointer<UInt8> = .allocate(capacity: 64)
	defer { pub.deallocate() }

	let c = privateKey.withUnsafeBytes { privPointer in
		compute_public_key_rfc6979(privPointer.baseAddress, pub, on.load)
	}

	if c == 0 {
		throw Error.invalidKey
	}

	return Data([4]) + Data(UnsafeBufferPointer(start: pub, count: 64))
}

func ethereumPublicKeyToAddressFrom(publicKey: Data) -> Data {
	var wrk = publicKey
	// remove the 0x04 prefix if present
	if publicKey.count == 65, publicKey[0] == 4 {
		wrk = publicKey[1 ..< 65]
	}
	return hash(.Keccak256, 256, wrk)[12 ..< 32]
}

func hexToDataFrom(string: String) -> Data? {
	let hexStr = string.dropFirst(string.hasPrefix("0x") ? 2 : 0)

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

func dataToHexFrom(data: Data) -> String {
	return data.map { String(format: "%02hhx", $0) }.joined()
}
