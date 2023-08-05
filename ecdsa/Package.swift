// swift-tools-version:5.7

import PackageDescription

let package = Package(
	name: "ecdsa",
	platforms: [
		.iOS(.v16),
		.macOS(.v13),
	],
	products: [
		.library(
			name: "ecdsa",
			targets: ["ecdsa/swift"]
		),
	],
	dependencies: [
	],
	targets: [
		.target(
			name: "ecdsa/swift",
			dependencies: [
				.target(name: "ecdsa/c"),
			],
			path: "./swift"
		),
		.target(
			name: "ecdsa/c",
			path: "./c",
			publicHeadersPath: "."
		),
		.testTarget(
			name: "ecdsa/tests",
			dependencies: [
				.target(name: "ecdsa/swift"),
			],
			path: "./tests"
		),
	]
)
