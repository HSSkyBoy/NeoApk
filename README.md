# NeoApk (NZA)

Pure Kotlin resilient ZIP engine, Android 16KB page-alignment utility, and APK V2+V3 scheme signer.

## Features

- **Pure Kotlin**: 100% Kotlin JVM library with zero Android framework runtime dependency (runs anywhere: JVM, CLI, Android).
- **Resilient ZIP Parser**: MT Manager-style fault-tolerant ZIP reading, stream repair, uncompressed host entry nesting, and zero-copy virtual entry linking.
- **16KB Page Alignment**: Built-in automated ABI-aware page alignment:
  - 16384 bytes (16KB) for 64-bit native libraries (`arm64-v8a`, `x86_64`) and nested APKs (`origin.apk`).
  - 4096 bytes (4KB) for 32-bit native libraries (`armeabi-v7a`, `x86`).
  - 4 bytes for `resources.arsc` and other stored entries.
- **APK V2 & V3 Scheme Signer**: Full APK Signature Scheme v2 and v3 support, including Android 15 APK Verity Tree builder, 2GB overflow protection, and APK Signing Block injection.

## Usage

### Gradle (JitPack)

```kotlin
repositories {
    mavenCentral()
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.HSSkyBoy:NeoApk:1.0.0")
}
```

### Basic Example

```kotlin
import top.nkbe.nza.zip.ZipFile
import top.nkbe.nza.zip.ZipMaker
import top.nkbe.nza.sign.V2V3SchemeSigner
import top.nkbe.nza.sign.GenericSignatureKey

// 1. Create APK with automatic 16KB/4KB alignment
ZipMaker(outputFile).use { maker ->
    maker.method = ZipMaker.METHOD_STORED
    maker.putNextEntry("lib/arm64-v8a/libnative.so")
    maker.write(nativeBytes)
    maker.closeEntry()
}

// 2. Sign APK with V2 + V3
V2V3SchemeSigner.sign(outputFile, signatureKey, enableV2 = true, enableV3 = true)
```

## License

Apache License 2.0
