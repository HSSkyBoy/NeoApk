package top.nkbe.nza

import com.android.apksig.ApkVerifier
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import top.nkbe.nza.sign.ApkSignatureReader
import top.nkbe.nza.sign.GenericSignatureKey
import top.nkbe.nza.sign.V2V3SchemeSigner
import top.nkbe.nza.zip.ZipFile
import top.nkbe.nza.zip.ZipMaker
import top.nkbe.nza.zip.ZipUtil
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Security
import java.security.cert.X509Certificate
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.Date

class ZipEdgeCasesTest {

    companion object {
        @BeforeClass
        @JvmStatic
        fun setupSecurityProvider() {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @get:Rule
    val tempFolder = TemporaryFolder()

    private fun newKey(): Pair<GenericSignatureKey, X509Certificate> {
        val keyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val now = System.currentTimeMillis()
        val name = X500Name("CN=NeoApk Edge Test, O=NKBE")
        val cert = JcaX509CertificateConverter().setProvider("BC").getCertificate(
            JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), Date(now - 10_000L), Date(now + 86_400_000L), name, keyPair.public
            ).build(JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private))
        )
        return GenericSignatureKey(keyPair.private, arrayOf(cert)) to cert
    }

    private fun newApk(comment: String? = null): File {
        val file = tempFolder.newFile()
        file.delete()
        ZipMaker(file).use { maker ->
            maker.comment = comment
            maker.putNextEntry("AndroidManifest.xml")
            maker.write("manifest".toByteArray())
            maker.closeEntry()
            maker.method = ZipMaker.METHOD_STORED
            maker.putNextEntry("lib/arm64-v8a/libx.so")
            maker.write(ByteArray(2048) { 0x33 })
            maker.closeEntry()
        }
        return file
    }

    @Test
    fun readsArchiveWithLongComment() {
        val file = newApk(comment = "c".repeat(5000))
        ZipFile(file).use { zip ->
            assertEquals(2, zip.entrySize)
            assertEquals("manifest", zip.getInputStream(zip.getEntryNonNull("AndroidManifest.xml")).bufferedReader().readText())
        }
    }

    @Test
    fun signsArchiveWithCommentAndReplacesExistingSignature() {
        val file = newApk(comment = "release build")
        val (firstKey, firstCert) = newKey()
        val (secondKey, secondCert) = newKey()

        V2V3SchemeSigner.sign(file, firstKey)
        assertArrayEquals(firstCert.encoded, ApkSignatureReader.getApkSignatures(file).single())

        V2V3SchemeSigner.sign(file, secondKey, enableV2 = false, enableV3 = true)
        val result = ApkVerifier.Builder(file).setMinCheckedPlatformVersion(28).build().verify()
        assertTrue(result.errors.joinToString(), result.isVerified)
        assertTrue(result.isVerifiedUsingV3Scheme)
        assertArrayEquals(secondCert.encoded, ApkSignatureReader.getApkSignatures(file).single())

        ZipFile(file).use { zip -> assertEquals(2, zip.entrySize) }
    }

    @Test
    fun unsignedArchiveHasNoSignatures() {
        val file = newApk()
        assertTrue(ApkSignatureReader.getApkSignatures(file).isEmpty())
        assertNull(ApkSignatureReader.getApkSignInfo(file))
    }

    @Test
    fun signingRequiresAtLeastOneScheme() {
        val file = newApk()
        val (key, _) = newKey()
        try {
            V2V3SchemeSigner.sign(file, key, enableV2 = false, enableV3 = false)
            throw AssertionError("expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
        }
    }

    @Test
    fun copyZipEntryPreservesContentAndDirectories() {
        val source = tempFolder.newFile()
        source.delete()
        val payload = ByteArray(100_000) { (it * 31).toByte() }
        ZipMaker(source).use { maker ->
            maker.putNextEntry("dir/")
            maker.closeEntry()
            maker.putNextEntry("dir/data.bin")
            maker.write(payload)
            maker.closeEntry()
        }

        val target = tempFolder.newFile()
        target.delete()
        ZipFile(source).use { zip ->
            ZipMaker(target).use { maker ->
                for (entry in zip.getEntries()) maker.copyZipEntry(entry, zip)
            }
        }

        ZipFile(target).use { zip ->
            assertTrue(zip.getEntryNonNull("dir/").isDirectory)
            assertArrayEquals(payload, zip.getInputStream(zip.getEntryNonNull("dir/data.bin")).readBytes())
        }
    }

    @Test
    fun dosTimeRoundTripIsDeterministic() {
        val local = LocalDateTime.of(2024, 5, 17, 13, 45, 30)
        val millis = local.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()
        val dos = ZipUtil.javaToDosTime(millis)
        assertEquals(millis, ZipUtil.dosToJavaTime(dos))
        assertEquals(millis, ZipUtil.dosToJavaTime(dos))
    }

    @Test
    fun dosTimeBefore1980IsClamped() {
        val millis = LocalDateTime.of(1970, 6, 1, 0, 0).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()
        val expected = LocalDateTime.of(1980, 1, 1, 0, 0).atZone(ZoneId.systemDefault()).toInstant().toEpochMilli()
        assertEquals(expected, ZipUtil.dosToJavaTime(ZipUtil.javaToDosTime(millis)))
    }
}
