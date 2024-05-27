// swift-tools-version:5.8

import PackageDescription

let package = Package(
	name: "micro-deterministic-ecdsa",
	platforms: [
		.iOS(.v16),
		.macOS(.v13),
	],
	products: [
		.library(
			name: "micro-deterministic-ecdsa",
			targets: ["MicroDeterministicECDSA"]
		),
	],
	dependencies: [],
	targets: [
		.target(
			name: "MicroDeterministicECDSA",
			dependencies: [],
			// path: "Sources/MicroDeterministicECDSA",
			publicHeadersPath: "../include"
		),
		.testTarget(
			name: "MicroDeterministicECDSATests",
			dependencies: ["MicroDeterministicECDSA"]
		),
	]
)
