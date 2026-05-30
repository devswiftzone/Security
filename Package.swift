// swift-tools-version: 6.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Security",
    platforms: [.macOS(.v13)],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(name: "SecurityKit", targets: ["SecurityKit"]),
        .library(name: "SecurityCore", targets: ["SecurityCore"]),
        .library(name: "SecurityFluent", targets: ["SecurityFluent"]),
        .library(name: "SecurityJWT", targets: ["SecurityJWT"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.92.0"),
        .package(url: "https://github.com/vapor/fluent.git", from: "4.9.0"),
        .package(url: "https://github.com/vapor/fluent-sqlite-driver.git", from: "4.6.0"),
        .package(url: "https://github.com/vapor/jwt.git", from: "5.0.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "SecurityKit",
            dependencies: [
                "SecurityCore",
                "SecurityFluent",
                "SecurityJWT",
            ]
        ),
        .target(
            name: "SecurityCore",
            dependencies: [
                .product(name: "Vapor", package: "vapor"),
                .product(name: "Fluent", package: "fluent"),
            ]),
        .target(
            name: "SecurityFluent",
            dependencies: [
                "SecurityCore",
                .product(name: "Fluent", package: "fluent"),
                .product(name: "Vapor", package: "vapor"),
            ]
        ),
        .target(
            name: "SecurityJWT",
            dependencies: [
                "SecurityCore",
                .product(name: "JWT", package: "jwt")
            ]
        ),
        .testTarget(
            name: "SecurityCoreTests",
            dependencies: [
                "SecurityCore",
                .product(name: "FluentSQLiteDriver", package: "fluent-sqlite-driver"),
            ]
        ),
        .testTarget(
            name: "SecurityFluentTests",
            dependencies: [
                "SecurityFluent",
                .product(name: "FluentSQLiteDriver", package: "fluent-sqlite-driver"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
