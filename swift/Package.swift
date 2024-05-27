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
			dependencies: ["MicroDeterministicECDSA_C"]
			// path: "Sources/MicroDeterministicECDSA",
			// publicHeadersPath: "include/public.h"
		),
		.target(
			name: "MicroDeterministicECDSA_C",
			dependencies: []
			// path: "Sources/MicroDeterministicECDSA",
			// publicHeadersPath: "include/public.h"
		),
		.testTarget(
			name: "MicroDeterministicECDSATests",
			dependencies: ["MicroDeterministicECDSA", "MicroDeterministicECDSA_C"]
		),
	]
)
