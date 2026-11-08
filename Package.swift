// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "SwiftCardanoSigner",
    platforms: [
        .iOS(.v16),
        .macOS(.v14),
        .watchOS(.v9),
        .tvOS(.v16),
        .visionOS(.v1),
    ],
    products: [
        .library(
            name: "SwiftCardanoSigner",
            targets: ["SwiftCardanoSigner"]
        ),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.0"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-core.git", from: "0.11.2"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-cips.git", from: "0.5.1"),
        .package(url: "https://github.com/Kingpin-Apps/swift-mnemonic.git", from: "0.2.7"),
        .package(url: "https://github.com/Kingpin-Apps/swift-nacl.git", .upToNextMinor(from: "2.0.0")),
    ],
    targets: [
        .target(
            name: "SwiftCardanoSigner",
            dependencies: [
                .product(name: "SwiftCardanoCore", package: "swift-cardano-core"),
                .product(name: "SwiftCardanoCIPs", package: "swift-cardano-cips"),
                .product(name: "SwiftMnemonic", package: "swift-mnemonic"),
                .product(name: "SwiftNaCl", package: "swift-nacl"),
                .product(
                    name: "Crypto",
                    package: "swift-crypto",
                    condition: .when(platforms: [.linux])
                ),
            ]
        ),
        .testTarget(
            name: "SwiftCardanoSignerTests",
            dependencies: ["SwiftCardanoSigner"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
