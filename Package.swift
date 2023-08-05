// swift-tools-version:5.8

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
			targets: ["RFC6979"]
		),
	],
	dependencies: [],
	targets: [
		.target(
			name: "CRFC6979"
			// cSettings: [.unsafeFlags(["-fprofile-instr-generate", "-fcoverage-mapping"])]
		),
		.target(
			name: "RFC6979",
			dependencies: ["CRFC6979"]
			// cSettings: [.unsafeFlags(["-fprofile-instr-generate", "-fcoverage-mapping"])]
		),
		.testTarget(
			name: "RFC6979Tests",
			dependencies: ["RFC6979", "CRFC6979"]
			// cSettings: [.unsafeFlags(["-fprofile-instr-generate", "-fcoverage-mapping"])]
		),
	]
)
