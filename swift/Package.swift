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
			targets: ["RFC6979"]
		),
	],
	dependencies: [],
	targets: [
		.target(
			name: "CRFC6979"
		),
		.target(
			name: "RFC6979",
			dependencies: ["CRFC6979"]
		),
		.testTarget(
			name: "RFC6979Tests",
			dependencies: ["RFC6979", "CRFC6979"]
		),
	]
)
