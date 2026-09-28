package top.nkbe.nza

import com.android.apksig.ApkVerifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import top.nkbe.nza.sign.GenericSignatureKey
import top.nkbe.nza.sign.V2V3SchemeSigner
import top.nkbe.nza.zip.ZipConstant
import top.nkbe.nza.zip.ZipFile
import top.nkbe.nza.zip.ZipMaker
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Security
import java.util.Date

class ZipAndSignTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setupSecurityProvider() {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @get:Rule
    val tempFolder = TemporaryFolder()

    @Test
    fun testZipMakerAlignmentAndReading() {
        val zipFileOnDisk = tempFolder.newFile("test_align.apk")
        zipFileOnDisk.delete()

        ZipMaker(zipFileOnDisk).use { maker ->
            // 1. Deflated entry
            maker.method = ZipMaker.METHOD_DEFLATED
            maker.putNextEntry("assets/test.txt")
            maker.write("Hello NeoApk Kotlin ZIP Engine!".toByteArray(Charsets.UTF_8))
            maker.closeEntry()

            // 2. Stored 64-bit native library (should be 16KB aligned)
            maker.method = ZipMaker.METHOD_STORED
            maker.putNextEntry("lib/arm64-v8a/libtest.so")
            val soData64 = ByteArray(8192) { 0x42 }
            maker.write(soData64)
            maker.closeEntry()

            // 3. Stored 32-bit native library (should be 4KB aligned)
            maker.method = ZipMaker.METHOD_STORED
            maker.putNextEntry("lib/armeabi-v7a/libtest.so")
            val soData32 = ByteArray(4096) { 0x24 }
            maker.write(soData32)
            maker.closeEntry()

            // 4. Stored resources.arsc (should be 4-byte aligned)
            maker.method = ZipMaker.METHOD_STORED
            maker.putNextEntry("resources.arsc")
            val arscData = ByteArray(1024) { 0x11 }
            maker.write(arscData)
            maker.closeEntry()
        }

        // Verify with ZipFile
        ZipFile(zipFileOnDisk).use { reader ->
            val textEntry = reader.getEntryNonNull("assets/test.txt")
            assertEquals(ZipConstant.METHOD_DEFLATED, textEntry.method)
            val textRead = reader.getInputStream(textEntry).bufferedReader().readText()
            assertEquals("Hello NeoApk Kotlin ZIP Engine!", textRead)

            val arm64Entry = reader.getEntryNonNull("lib/arm64-v8a/libtest.so")
            assertEquals(ZipConstant.METHOD_STORED, arm64Entry.method)
            assertEquals("arm64-v8a .so must be 16KB (16384 bytes) aligned", 0L, arm64Entry.dataOffset % 16384)

            val arm32Entry = reader.getEntryNonNull("lib/armeabi-v7a/libtest.so")
            assertEquals(ZipConstant.METHOD_STORED, arm32Entry.method)
            assertEquals("32-bit .so must be 4KB (4096 bytes) aligned", 0L, arm32Entry.dataOffset % 4096)

            val arscEntry = reader.getEntryNonNull("resources.arsc")
            assertEquals(ZipConstant.METHOD_STORED, arscEntry.method)
            assertEquals("resources.arsc must be 4-byte aligned", 0L, arscEntry.dataOffset % 4)
        }
    }

    @Test
    fun testApkSigningV2V3() {
        val apkFile = tempFolder.newFile("sample_app.apk")
        apkFile.delete()

        // Create a minimal valid APK zip
        ZipMaker(apkFile).use { maker ->
            maker.method = ZipMaker.METHOD_DEFLATED
            maker.putNextEntry("AndroidManifest.xml")
            maker.write("dummy manifest content".toByteArray(Charsets.UTF_8))
            maker.closeEntry()

            maker.putNextEntry("classes.dex")
            maker.write("dummy dex content".toByteArray(Charsets.UTF_8))
            maker.closeEntry()

            maker.method = ZipMaker.METHOD_STORED
            maker.putNextEntry("lib/arm64-v8a/libnative.so")
            maker.write(ByteArray(1024) { 0x55 })
            maker.closeEntry()
        }

        // Generate self-signed RSA test key pair and cert
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val keyPair = kpg.generateKeyPair()

        val now = System.currentTimeMillis()
        val notBefore = Date(now - 10_000L)
        val notAfter = Date(now + 365L * 24 * 3600 * 1000)
        val name = X500Name("CN=NeoApk Test Signer, O=NKBE")
        val certBuilder = JcaX509v3CertificateBuilder(
            name,
            BigInteger.valueOf(System.currentTimeMillis()),
            notBefore,
            notAfter,
            name,
            keyPair.public
        )
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val certHolder = certBuilder.build(signer)
        val cert = JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder)

        val sigKey = GenericSignatureKey(keyPair.private, arrayOf(cert))

        // Sign with V2 + V3
        V2V3SchemeSigner.sign(apkFile, sigKey, enableV2 = true, enableV3 = true)

        // Verify with official Android ApkVerifier
        val verifier = ApkVerifier.Builder(apkFile)
            .setMinCheckedPlatformVersion(24)
            .build()
        val result = verifier.verify()
        assertTrue("APK verification must succeed", result.isVerified)
        assertTrue("V2 scheme must be verified", result.isVerifiedUsingV2Scheme)
        assertTrue("V3 scheme must be verified", result.isVerifiedUsingV3Scheme)
    }

    @Test
    fun testHostAndVirtualEntryAlignment() {
        val innerApkFile = tempFolder.newFile("inner.apk")
        innerApkFile.delete()

        val arm64Bytes = ByteArray(8192) { (it % 251).toByte() }
        val arm32Bytes = ByteArray(4096) { (it % 199).toByte() }
        val txtBytes = "Inner APK text content".toByteArray(Charsets.UTF_8)

        // 1. Create inner APK with 16KB aligned arm64 .so
        ZipMaker(innerApkFile).use { maker ->
            maker.method = ZipMaker.METHOD_DEFLATED
            maker.putNextEntry("assets/inner.txt")
            maker.write(txtBytes)
            maker.closeEntry()

            maker.method = ZipMaker.METHOD_STORED
            maker.putNextEntry("lib/arm64-v8a/libinner.so")
            maker.write(arm64Bytes)
            maker.closeEntry()

            maker.method = ZipMaker.METHOD_STORED
            maker.putNextEntry("lib/armeabi-v7a/libinner32.so")
            maker.write(arm32Bytes)
            maker.closeEntry()
        }

        // Verify inner APK offsets
        ZipFile(innerApkFile).use { innerZip ->
            val innerSo64 = innerZip.getEntryNonNull("lib/arm64-v8a/libinner.so")
            assertEquals("Inner arm64 .so must be 16KB aligned", 0L, innerSo64.dataOffset % 16384)
            val innerSo32 = innerZip.getEntryNonNull("lib/armeabi-v7a/libinner32.so")
            assertEquals("Inner 32-bit .so must be 4KB aligned", 0L, innerSo32.dataOffset % 4096)
        }

        // 2. Create outer APK embedding inner.apk as host entry and exposing virtual entries
        val outerApkFile = tempFolder.newFile("outer.apk")
        outerApkFile.delete()

        ZipFile(innerApkFile).use { innerZip ->
            ZipMaker(outerApkFile).use { outerMaker ->
                outerMaker.method = ZipMaker.METHOD_DEFLATED
                outerMaker.putNextEntry("classes.dex")
                outerMaker.write("outer classes dex".toByteArray(Charsets.UTF_8))
                outerMaker.closeEntry()

                // Embed inner.apk as host entry
                val hostHolder = outerMaker.putNextHostEntry("assets/npatch/origin.apk", innerZip)

                // Expose virtual entries
                hostHolder.putNextVirtualEntry("lib/arm64-v8a/libinner.so")
                hostHolder.putNextVirtualEntry("lib/armeabi-v7a/libinner32.so")
            }
        }

        // 3. Verify outer APK
        ZipFile(outerApkFile).use { outerZip ->
            val hostEntry = outerZip.getEntryNonNull("assets/npatch/origin.apk")
            assertEquals(ZipConstant.METHOD_STORED, hostEntry.method)
            assertEquals("assets/npatch/origin.apk must be 16KB aligned", 0L, hostEntry.dataOffset % 16384)

            val vEntry64 = outerZip.getEntryNonNull("lib/arm64-v8a/libinner.so")
            assertNotNull("Virtual arm64 entry must exist in outer central directory", vEntry64)
            assertEquals("Virtual arm64 .so must be 16KB aligned in outer APK", 0L, vEntry64.dataOffset % 16384)
            val read64 = outerZip.getInputStream(vEntry64).readBytes()
            assertTrue("Virtual arm64 .so content must match", arm64Bytes.contentEquals(read64))

            val vEntry32 = outerZip.getEntryNonNull("lib/armeabi-v7a/libinner32.so")
            assertNotNull("Virtual arm32 entry must exist in outer central directory", vEntry32)
            assertEquals("Virtual arm32 .so must be 4KB aligned in outer APK", 0L, vEntry32.dataOffset % 4096)
            val read32 = outerZip.getInputStream(vEntry32).readBytes()
            assertTrue("Virtual arm32 .so content must match", arm32Bytes.contentEquals(read32))
        }
    }
}
