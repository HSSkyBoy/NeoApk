# NeoApk

[![Build and Test](https://github.com/HSSkyBoy/NeoApk/actions/workflows/build.yml/badge.svg)](https://github.com/HSSkyBoy/NeoApk/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/HSSkyBoy/NeoApk?color=brightgreen)](https://github.com/HSSkyBoy/NeoApk/releases)

**NeoApk (`top.nkbe.nza`)** is a high-performance, fault-tolerant pure Kotlin ZIP engine, ABI-aware 16KB page-alignment utility, and APK Signature Scheme v2 & v3 signer tailored for modern Android packaging and modding pipelines.

Designed as a modern, clean-room replacement for fragile legacy libraries like `apkzlib` and external C binaries (`zipalign`, `apksigner`), NeoApk runs anywhere on the JVM, CLI, or Android runtime without external native dependencies.

---

## Features

### 1. Resilient Pure Kotlin ZIP Engine (`top.nkbe.nza.zip`)
- **Zero Android Framework Dependency**: 100% Kotlin JVM implementation. Runs seamlessly across desktop CLI, server pipelines, and Android apps.
- **MT Manager-Grade Fault Tolerance**: Tolerant of malformed, truncated, or non-standard Central Directory and Local File Headers commonly found in protected or modded APKs.
- **High-Throughput Streaming**: Custom `BufferedRandomAccess` (default 128KB circular buffer) and `BridgeInputStream`/`BridgeOutputStream` for high I/O throughput with minimal memory footprint.
- **Native Host Nesting & Zero-Copy Virtual Entries**:
  - `putNextHostEntry`: Writes nested APKs (e.g. `origin.apk`) with exact uncompressed (STORED) page alignment.
  - `putNextVirtualEntry`: Maps files inside the host APK directly into the outer APK's Central Directory without unpacking, saving substantial disk space and build time.
- **Complete ZIP64 Support**: Seamlessly handles APK archives exceeding 4GB and 65,535 entries.

### 2. ABI-Aware 16KB Page Alignment
Automatically inspects entry names and architectures to enforce strict Google Play and Android 15+ kernel memory-mapping compliance:
- **16384 Bytes (16KB) Alignment**:
  - 64-bit native libraries: `lib/arm64-v8a/*.so`, `lib/x86_64/*.so`
  - Nested APKs and binary images: `assets/**/origin.apk`, `origin_apk.bin`, etc.
  - Virtual entries mapped via `putNextVirtualEntry` maintain 16KB alignment automatically when the host APK is aligned.
- **4096 Bytes (4KB) Alignment**: 32-bit native libraries (`armeabi-v7a`, `x86`).
- **4 Bytes Alignment**: `resources.arsc` and all other uncompressed (STORED) entries.

### 3. APK Signature Scheme V2 & V3 Signer (`top.nkbe.nza.sign`)
- **Dual Scheme (v2 + v3) Signing**: Produces standard APK Signing Blocks fully compatible with Android 7.0 through Android 16+.
- **APK Verity Tree Builder**: Built-in Merkle tree calculation with an integer overflow workaround for APKs exceeding 2GB on Android 15.
- **Preserves Existing Signatures & Metadata**: Injects the signing block immediately before the Central Directory without altering or stripping existing `META-INF/` entries (essential for signature bypass and integrity checks).
- **Keystore Flexibility**: Supports BKS, JKS, PKCS12 keystores and in-memory key pairs.

---

## Architecture

```
top.nkbe.nza
├── data
│   ├── buffer    # High-throughput buffered random access (BufferedRandomAccess)
│   ├── source    # File, memory, and fragmented random access abstractions
│   └── stream    # CRC calculation, raw Deflate/Inflate, and zero-copy bridges
├── zip
│   ├── ZipFile   # Resilient, fault-tolerant ZIP archive reader
│   ├── ZipMaker  # ABI-aware, alignment-enforcing ZIP archive creator
│   └── ...       # ExtraDataRecord, CenterFileHeader, ZipEntry
└── sign
    ├── V2V3SchemeSigner # Core APK v2 & v3 scheme signer
    ├── VerityTreeBuilder# APK Verity tree generator with >2GB safety
    └── SignatureKey     # Key abstraction and certificates wrapper
```

---

## Installation

### 1. Gradle (JitPack)

In `settings.gradle.kts`:

```kotlin
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}
```

In `build.gradle.kts`:

```kotlin
dependencies {
    implementation("com.github.HSSkyBoy:NeoApk:v1.0.0")
}
```

### 2. Gradle Composite Build (Local Development)

In `settings.gradle.kts`:

```kotlin
val neoApkDir = file("../NeoApk")
if (neoApkDir.exists()) {
    includeBuild(neoApkDir) {
        dependencySubstitution {
            substitute(module("top.nkbe:NeoApk")).using(project(":"))
        }
    }
}
```

In `build.gradle.kts`:

```kotlin
dependencies {
    implementation("top.nkbe:NeoApk:1.0.0")
}
```

---

## Quick Start

### 1. Create and Align an APK

```kotlin
import top.nkbe.nza.zip.ZipMaker
import java.io.File

val apkFile = File("patched_app.apk")

ZipMaker(apkFile).use { maker ->
    // Deflated entry
    maker.method = ZipMaker.METHOD_DEFLATED
    maker.putNextEntry("AndroidManifest.xml")
    maker.write(manifestBytes)
    maker.closeEntry()

    // Stored 64-bit native library (automatically 16KB aligned)
    maker.method = ZipMaker.METHOD_STORED
    maker.putNextEntry("lib/arm64-v8a/libnative.so")
    maker.write(soBytes)
    maker.closeEntry()
}
```

### 2. Host APK Nesting & Zero-Copy Virtual Entry Mapping

```kotlin
import top.nkbe.nza.zip.ZipFile
import top.nkbe.nza.zip.ZipMaker

ZipFile(originalApk).use { srcZip ->
    ZipMaker(outputApk).use { maker ->
        maker.putNextEntry("AndroidManifest.xml")
        maker.write(newManifestBytes)
        maker.closeEntry()

        // Embed original APK as a 16KB-aligned host entry
        val hostHolder = maker.putNextHostEntry("assets/npatch/origin.apk", srcZip)

        // Expose entries from origin.apk directly in the outer Central Directory
        hostHolder.putNextVirtualEntry("lib/arm64-v8a/libnative.so")
        hostHolder.putNextVirtualEntry("resources.arsc")
    }
}
```

### 3. V2 & V3 APK Signing

```kotlin
import top.nkbe.nza.sign.V2V3SchemeSigner
import top.nkbe.nza.sign.GenericSignatureKey
import java.security.KeyStore
import java.security.cert.X509Certificate

val keyStore = KeyStore.getInstance("BKS").apply {
    keyStoreFile.inputStream().use { load(it, password) }
}
val entry = keyStore.getEntry(alias, KeyStore.PasswordProtection(password)) as KeyStore.PrivateKeyEntry
val sigKey = GenericSignatureKey(
    entry.privateKey,
    entry.certificateChain.map { it as X509Certificate }.toTypedArray()
)

// Sign APK with v2 and v3 schemes
V2V3SchemeSigner.sign(
    apkFile = outputFile,
    signatureKey = sigKey,
    enableV2 = true,
    enableV3 = true
)
```

---

## License

NeoApk is licensed under the [Apache License, Version 2.0](LICENSE).
