// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "MyApp",
    platforms: [.macOS(.v13)],
    dependencies: [
        // @snippet(dep)
        .package(url: "https://github.com/devswiftzone/Security.git", from: "0.1.0")
        // @endSnippet(dep)
    ],
    targets: [
        // @snippet(target)
        .executableTarget(
            name: "App",
            dependencies: [
                .product(name: "SecurityKit", package: "Security"),
            ]
        )
        // @endSnippet(target)
    ]
)
