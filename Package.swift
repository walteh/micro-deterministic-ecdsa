// swift-tools-version:5.9

import PackageDescription

let package = Package(
	name: "MicroDeterministicECDSA",
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
			name: "MicroDeterministicECDSA_src",
			dependencies: [],
			path: "src"
		),

		.target(
			name: "MicroDeterministicECDSA",
			dependencies: ["MicroDeterministicECDSA_src"],
			path: "swift/Sources/MicroDeterministicECDSA"
		),

		.testTarget(
			name: "MicroDeterministicECDSATests",
			dependencies: ["MicroDeterministicECDSA", "MicroDeterministicECDSA_src"],
			path: "swift/Tests/MicroDeterministicECDSATests"
		),
	]
)
