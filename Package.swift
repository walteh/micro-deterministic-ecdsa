// swift-tools-version:5.9

import PackageDescription

let package = Package(
	name: "micro-deterministic-ecdsa",
	platforms: [
		.iOS(.v17),
		.macOS(.v14),
	],
	products: [
		.library(
			name: "MicroDeterministicECDSA",
			targets: ["MicroDeterministicECDSA"]
		),
	],
	dependencies: [],
	targets: [
		.target(
			name: "MicroDeterministicECDSA-Src",
			dependencies: [],
			path: "src"
		),

		.target(
			name: "MicroDeterministicECDSA",
			dependencies: ["MicroDeterministicECDSA-Src"],
			path: "swift/Sources/MicroDeterministicECDSA"
		),

		.testTarget(
			name: "MicroDeterministicECDSATests",
			dependencies: ["MicroDeterministicECDSA", "MicroDeterministicECDSA-Src"],
			path: "swift/Tests/MicroDeterministicECDSATests"
		),
	]
)
