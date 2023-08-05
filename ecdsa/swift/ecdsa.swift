//
//  micro-ecc.swift
//
//  Created by walteh on 12/5/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
//

import Foundation

import ecdsa_c

public enum ecdsa {
	public enum Error: Swift.Error {
		case invalidKey
		case invalidSignature
		case invalidHash
		case invalidCurve
		case invalidStrategy
		case invalidRecID
	}

	public typealias Curve = curve
	public typealias Strategy = strategy
	public typealias Signature = signature
}

public enum curve {
	case secp256k1
	var load: uECC_Curve {
		switch self {
		case .secp256k1: return uECC_secp256k1()
		}
	}
}

public enum strategy {
	case recoverable
	// case eth_message
	case eth_tx

	var hasher: (Data) -> Data {
		switch self {
		case .recoverable, .eth_tx: return { x in x.sha3(.ethereum) }
			// case .eth_message: return { x in "\\x19Ethereum Signed Message:\\n32\(x.sha3(.ethereum).hexEncodedString(prefixed: false))".data(using: .utf8)!.sha3(.ethereum) }
		}
	}

	var buildRecID: (UInt8) -> UInt8 {
		switch self {
		case .recoverable: return { x in x }
		case .eth_tx: return { x in x + 27 }
			//
			// case .eth_message: return { x in x + 27 }
		}
	}
}

public struct signature {
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

public func sign_raw(_ curve: curve, _ strategy: strategy, message: Data, privateKey: Data) throws -> signature {
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
		throw ecdsa.Error.invalidKey
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
