//
//  KeccakTiny.swift
//
//  Created by walteh on 11/23/22.
//  Copyright © 2022 Walter Scott. All rights reserved.
//

import Foundation

import ecdsa_c

public enum Varient {
	case ethereum
	case standard
}

private func c_sha3(_ data: Data, with: Varient) -> Data {
	let nsData = data as NSData
	let input = nsData.bytes.bindMemory(to: UInt8.self, capacity: data.count)
	let result = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)

	switch with {
	case .ethereum: sha3_ethereum256(result, 32, input, data.count)
	case .standard: sha3_256(result, 32, input, data.count)
	}

	return Data(bytes: result, count: 32)
}

public extension Data {
	func sha3(_ varient: Varient) -> Data {
		return c_sha3(self, with: varient)
	}
}
