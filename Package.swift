// swift-tools-version:5.7

import PackageDescription

let package = Package(
	name: "swift-rfc6979",
	platforms: [
		.iOS(.v16),
		.macOS(.v13),
	],
	products: [
		.library(
			name: "swift-rfc6979",
			targets: ["SwiftRFC6979"]
		),
	],
	dependencies: [],
	targets: [
		.target(name: "C/sha3"),
		.target(name: "C/rfc6979"),
		.target(name: "SwiftRFC6979", dependencies: ["C/sha3", "C/rfc6979"]),
		.testTarget(name: "SwiftRFC6979Tests", dependencies: ["SwiftRFC6979"]),
	]
)
