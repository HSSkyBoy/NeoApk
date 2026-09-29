# NeoApk

[![Build and Test](https://github.com/HSSkyBoy/NeoApk/actions/workflows/build.yml/badge.svg)](https://github.com/HSSkyBoy/NeoApk/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/HSSkyBoy/NeoApk?color=brightgreen)](https://github.com/HSSkyBoy/NeoApk/releases)

**NeoApk** (package `top.nkbe.nza`) is a pure Kotlin/JVM library for building, aligning, and signing Android APKs. It bundles three things that APK repackaging tools usually get from separate places:

- a fault-tolerant **ZIP reader/writer** (replaces `apkzlib`),
- **ABI-aware page alignment** including 16KB (replaces `zipalign`),
- an **APK Signature Scheme v2/v3 signer** and **signature reader** (replaces `apksigner`).

It has no runtime dependencies, needs no native binaries, and runs on desktop JVMs and on Android alike. It is the packaging engine behind [NPatch](https://github.com/7723mod/NPatch), which is the best reference for real-world usage (see [Real-world usage](#real-world-usage-npatch)).

---

## Features

### ZIP engine (`top.nkbe.nza.zip`)
- **Tolerant reader**: `ZipFile` parses archives with malformed, truncated, or non-standard headers commonly found in protected or modded APKs.
- **Streaming writer**: `ZipMaker` writes entries sequentially over a buffered random-access file (128KB buffer by default).
- **Raw entry copy**: `ZipMaker.copyZipEntry` copies an entry's compressed bytes as-is, with no inflate/deflate round-trip.
- **Host entries and virtual entries**:
  - `putNextHostEntry` embeds a whole APK (for example `assets/npatch/origin.apk`) as a STORED, page-aligned entry.
  - `putNextVirtualEntry` exposes files of that embedded APK in the outer Central Directory without copying them, so the outer APK can be smaller and faster to build.
- **ZIP64**: archives over 4GB or with more than 65,535 entries are supported.

### Page alignment
`ZipMaker` aligns STORED entries automatically using `ZipMaker.defaultAlignment`:

| Entry | Alignment |
|-------|-----------|
| Host entries, `*origin.apk`, `*origin_apk.bin`, `assets/{npatch,lspatch}/origin.apk`, `assets/origin.apk` | 16384 (16KB) |
| `lib/arm64-v8a/*.so`, `lib/x86_64/*.so` | 16384 (16KB) |
| Other `.so` files (`armeabi-v7a`, `x86`, ...) | 4096 (4KB) |
| `resources.arsc` and every other STORED entry | 4 |

Virtual entries inherit their alignment from the host, so they stay 16KB-aligned when the host entry is. To use a different policy, assign `ZipMaker.alignmentRule`.

### Signing (`top.nkbe.nza.sign`)
- **`V2V3SchemeSigner`** signs an APK in place with APK Signature Scheme v2 and/or v3. The v3 block declares SDK range 28 to `Int.MAX_VALUE`.
- **APK Verity**: a Merkle-tree padding/digest is added when the APK is at most 2GB. Above 2GB the verity algorithms are dropped to avoid an integer overflow in Android 15's verity builder.
- **Signing block replacement**: any existing APK Signing Block is replaced by the new one, which is inserted right before the Central Directory. `META-INF/` entries are never touched, so a v1 signature already in the APK stays as it is.
- **`ApkSignatureReader`** extracts the signer certificates of an APK from the v3/v3.1, v2, or v1 signature (in that order of preference), with no dependencies. It returns the same hex form as Android's `Signature.toCharsString()`, which is what signature-bypass hooks compare against.
- **Keys**: `SignatureKey` / `GenericSignatureKey` wrap any `PrivateKey` plus certificate chain, so keys can come from BKS, JKS, PKCS12, or memory.
  Reading a BKS keystore needs a BouncyCastle provider on the JVM. Android ships one.
  RSA (PSS and PKCS#1 v1.5), ECDSA, and DSA keys are supported.

---

## Architecture

```
top.nkbe.nza
├── zip
│   ├── ZipFile              # Fault-tolerant reader (entries, streams, nested ZIPs)
│   ├── ZipMaker             # Writer: alignment, host/virtual entries, raw copy
│   ├── ZipEntry             # Entry metadata as read from an archive
│   └── ZipConstant, ZipUtil, CenterFileHeader, ExtraDataRecord
├── sign
│   ├── V2V3SchemeSigner     # v2 + v3 signer (in place)
│   ├── ApkSignatureReader   # Certificate extraction: v3/v3.1, v2, v1
│   ├── SignatureKey         # SignatureKey interface + GenericSignatureKey
│   ├── SignatureAlgorithm   # Algorithm registry and digest computation
│   ├── VerityTreeBuilder    # APK Verity Merkle tree
│   └── ZipBuffer, data/*    # Layout parsing and chunked data sources used for digests
└── data
    ├── buffer               # BufferedRandomAccess, RandomAccessFactory
    ├── source               # File / memory / fragment RandomAccessData
    └── stream               # Bridge streams, CRC, raw Deflate/Inflate
```

---

## Requirements

- JDK 21 (the library is compiled with a Java 21 toolchain).
- Kotlin 2.1.x if you build it from source. Consumers can be plain Java, since the public API is `@JvmStatic`/`@Throws`-annotated.

---

## Installation

The library coordinates are `top.nkbe:NeoApk:1.0.1`.

### Local Maven

```
./gradlew publishToMavenLocal
```

```kotlin
repositories { mavenLocal() }
dependencies { implementation("top.nkbe:NeoApk:1.0.1") }
```

### Composite build (local development)

Clone NeoApk next to your project and substitute it. This is how NPatch consumes it:

```kotlin
// settings.gradle.kts
val neoApkDir = file("../NeoApk")
if (neoApkDir.exists()) {
    includeBuild(neoApkDir) {
        dependencySubstitution {
            substitute(module("top.nkbe:NeoApk")).using(project(":"))
        }
    }
}
```

```kotlin
// build.gradle.kts
dependencies {
    implementation("top.nkbe:NeoApk:1.0.1")
}
```

If the sibling directory does not exist, the substitution is skipped and `top.nkbe:NeoApk:1.0.1` has to resolve from a repository (for example `mavenLocal()`).

---

## Usage

### 1. Read an APK

`ZipFile` opens the archive lazily and indexes entries by name.

```kotlin
import top.nkbe.nza.zip.ZipFile
import java.io.File

ZipFile(File("app.apk")).use { zip ->
    val manifest = zip.getEntry("AndroidManifest.xml") ?: error("not an apk")
    zip.getInputStream(manifest).use { input -> /* decompressed bytes */ }

    for (entry in zip.getEntries()) {
        println("${entry.name} method=${entry.method} size=${entry.size}")
    }
}
```

- `getInputStream(entry)` returns decompressed data. `getRawInputStream(entry)` returns the stored/compressed bytes untouched.
- `getEntry(name)` returns `null` for a missing entry. `getEntryNonNull(name)` throws `IOException`.
- `openEntryAsZipFile(entry)` opens a STORED entry (a nested APK, for instance) as a `ZipFile` without extracting it.

### 2. Create an aligned APK

```kotlin
import top.nkbe.nza.zip.ZipMaker
import java.io.File

ZipMaker(File("out.apk")).use { maker ->
    // DEFLATED is the default method
    maker.putNextEntry("AndroidManifest.xml")
    maker.write(manifestBytes)
    maker.closeEntry()

    // STORED 64-bit library: aligned to 16KB automatically
    maker.method = ZipMaker.METHOD_STORED
    maker.putNextEntry("lib/arm64-v8a/libnative.so")
    maker.write(soBytes)      // or maker.writeFully(inputStream)
    maker.closeEntry()
    maker.method = ZipMaker.METHOD_DEFLATED
}
```

`ZipMaker(file)` deletes an existing file at that path. Settings available on the maker: `method`, `level` (`LEVEL_FASTEST` to `LEVEL_BEST`), `encoding`, `comment`, `isForceZip64`, and `alignmentRule`.

### 3. Repack: copy, convert, and skip entries

`copyZipEntry` reuses the compressed bytes. When an entry needs a different storage method, for example to re-store `.so` files and `resources.arsc` so they can be aligned, rewrite it:

```kotlin
ZipFile(srcApk).use { src ->
    ZipMaker(outApk).use { maker ->
        for (entry in src.getEntries()) {
            val name = entry.name
            val mustBeStored = name.endsWith(".so") || name == "resources.arsc"
            if (mustBeStored && entry.method != ZipConstant.METHOD_STORED) {
                maker.method = ZipMaker.METHOD_STORED
                maker.putNextEntry(name)
                src.getInputStream(entry).use { maker.writeFully(it) }
                maker.closeEntry()
                maker.method = ZipMaker.METHOD_DEFLATED
            } else {
                maker.copyZipEntry(entry, src)
            }
        }
    }
}
```

### 4. Embed the original APK with host and virtual entries

```kotlin
ZipFile(originalApk).use { src ->
    ZipMaker(outputApk).use { maker ->
        // Modified manifest, written normally
        maker.putNextEntry("AndroidManifest.xml")
        maker.write(newManifestBytes)
        maker.closeEntry()

        // The whole original APK as one STORED, 16KB-aligned entry
        val host = maker.putNextHostEntry("assets/npatch/origin.apk", src)

        // Make selected files of the original show up in the outer APK
        // without copying their bytes a second time
        for (entry in src.getEntries()) {
            if (entry.name == "AndroidManifest.xml") continue
            host.putNextVirtualEntry(entry.name)
        }
    }
}
```

A virtual entry reuses the host's local file header and data, so the entry should keep the compression method it has in the original APK. `putNextVirtualEntry` throws `IOException` if the name is not in the source archive, so callers can catch it and fall back to `copyZipEntry` (NPatch does this).

### 5. Sign with v2 and v3

```kotlin
import top.nkbe.nza.sign.GenericSignatureKey
import top.nkbe.nza.sign.V2V3SchemeSigner
import java.security.KeyStore
import java.security.cert.X509Certificate

val keyStore = KeyStore.getInstance("BKS").apply {
    keystoreFile.inputStream().use { load(it, storePassword) }
}
val entry = keyStore.getEntry(alias, KeyStore.PasswordProtection(keyPassword)) as KeyStore.PrivateKeyEntry
val key = GenericSignatureKey(
    entry.privateKey,
    entry.certificateChain.map { it as X509Certificate }.toTypedArray()
)

V2V3SchemeSigner.sign(file = outputApk, signatureKey = key, enableV2 = true, enableV3 = true)
```

Notes:
- The APK is modified in place, so sign it after `ZipMaker` has been closed.
- Sign last. Any change to the ZIP contents afterwards invalidates v2/v3.
- At least one of `enableV2` and `enableV3` must be true.

### 6. Read APK signatures

```kotlin
import top.nkbe.nza.sign.ApkSignatureReader

val certs: List<ByteArray> = ApkSignatureReader.getApkSignatures(apkFile) // DER certificates
val hex: String? = ApkSignatureReader.getApkSignInfo(apkFile)             // first cert, hex; null if unsigned
val chars: CharArray = ApkSignatureReader.toChars(certs[0])
```

Failures (unreadable file, corrupt signing block) return an empty list or `null` instead of throwing.

### From Java

Everything above is callable from Java. `V2V3SchemeSigner` and `ApkSignatureReader` are Kotlin objects with `@JvmStatic` members. Default arguments only exist on the Kotlin side, so pass all four arguments of `sign`:

```java
V2V3SchemeSigner.sign(outputFile, signatureKey, true, true);
String sig = ApkSignatureReader.getApkSignInfo(new File(path));
```

---

## Real-world usage: NPatch

[NPatch](https://github.com/7723mod/NPatch) uses NeoApk end to end in its `patch` module (`NPatch.java`). It is a good reference for how the pieces fit together:

| NPatch step | NeoApk API |
|-------------|------------|
| Parse the source APK's manifest | `ZipFile.getEntry`, `getInputStream` |
| Write the patched manifest and injected loader dex/native libraries | `ZipMaker.putNextEntry`, `writeFully`, `closeEntry`, `method` |
| Re-store `.so` / `resources.arsc` so they can be aligned | `ZipMaker.METHOD_STORED`, `ZipConstant.METHOD_STORED` |
| Keep the original APK as `assets/npatch/origin.apk` | `putNextHostEntry` |
| Link the original's other files without copying | `HostEntryHolder.putNextVirtualEntry`, falling back to `copyZipEntry` |
| Copy split APK entries as they are | `copyZipEntry` |
| Read the original signature for signature bypass | `ApkSignatureReader.getApkSignInfo` |
| Sign with the built-in or a user keystore | `GenericSignatureKey`, `V2V3SchemeSigner.sign(file, key, true, true)` |

---

## Building and testing

```
./gradlew test build
```

The tests in `src/test` cover alignment, host/virtual entries, and v2/v3 signing. The signing tests are verified against Google's `apksig` (test dependency only).

---

## License

NeoApk is licensed under the [Apache License, Version 2.0](LICENSE).
