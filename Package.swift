// swift-tools-version:5.7

import PackageDescription

let package = Package(
	name: "swift-ecc",
	platforms: [
		.iOS(.v16),
		.macOS(.v13),
	],
	products: [
		.library(
			name: "swift-ecc",
			targets: ["SwiftECC"]
		),
	],
	dependencies: [],
	targets: [
		.target(name: "C/sha3"),
		.target(name: "C/rfc6979"),
		.target(name: "SwiftECC", dependencies: ["C/sha3", "C/rfc6979"]),
		.testTarget(name: "SwiftECCTests", dependencies: ["SwiftECC"]),
	]
)
