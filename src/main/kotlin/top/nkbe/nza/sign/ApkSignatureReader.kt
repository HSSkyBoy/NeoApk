package top.nkbe.nza.sign

import top.nkbe.nza.data.buffer.RandomAccessFactory
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Lightweight, zero-dependency APK signature extractor supporting Scheme v1, v2, v3, and v3.1.
 */
object ApkSignatureReader {

    private const val APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
    private const val APK_SIGNATURE_SCHEME_V3_BLOCK_ID = -0x0fac9740 // 0xf05368c0
    private const val APK_SIGNATURE_SCHEME_V31_BLOCK_ID = 0x1b93ad61

    /**
     * Extracts raw DER-encoded certificate byte arrays from APK signing blocks (v3, v2, or v1 fallback).
     */
    @JvmStatic
    fun getApkSignatures(apkFile: File): List<ByteArray> {
        if (!apkFile.isFile) return emptyList()
        try {
            // 1. Try V3 / V2 via APK Signing Block
            val v2v3Signatures = getV2V3Signatures(apkFile)
            if (v2v3Signatures.isNotEmpty()) {
                return v2v3Signatures
            }

            // 2. Fallback to V1 (JAR signature in META-INF)
            val v1Signatures = getV1Signatures(apkFile)
            if (v1Signatures.isNotEmpty()) {
                return v1Signatures
            }
        } catch (_: Exception) {
        }
        return emptyList()
    }

    /**
     * Returns the hex-encoded string of the first signer certificate (matching Android's Signature.toCharsString()).
     */
    @JvmStatic
    fun getApkSignInfo(apkFile: File): String? {
        val signatures = getApkSignatures(apkFile)
        return if (signatures.isNotEmpty()) {
            toCharsString(signatures[0])
        } else {
            null
        }
    }

    /**
     * Converts a raw certificate byte array to the hex char array matching Android's Signature.toChars().
     */
    @JvmStatic
    fun toChars(signature: ByteArray): CharArray {
        val n = signature.size
        val n2 = n * 2
        val text = CharArray(n2)
        for (j in 0 until n) {
            val v = signature[j].toInt() and 0xff
            var d = (v ushr 4) and 0xf
            text[j * 2] = if (d >= 10) ('a' + d - 10) else ('0' + d)
            d = v and 0xf
            text[j * 2 + 1] = if (d >= 10) ('a' + d - 10) else ('0' + d)
        }
        return text
    }

    /**
     * Converts a raw certificate byte array to the hex string matching Android's Signature.toCharsString().
     */
    @JvmStatic
    fun toCharsString(signature: ByteArray): String {
        return String(toChars(signature))
    }

    private fun getV2V3Signatures(apkFile: File): List<ByteArray> {
        RandomAccessFactory.from(apkFile, "r").use { accessFile ->
            val zipBuffer = ZipBuffer(accessFile)
            if (!zipBuffer.hasApkSigBlock) return emptyList()

            val cdOffset = zipBuffer.centralDirectoryOffset
            accessFile.seek(cdOffset - 24)
            val blockSize = accessFile.readLong()
            val pairsEnd = cdOffset - 24
            var currentPos = cdOffset - blockSize

            val v3Certs = mutableListOf<ByteArray>()
            val v2Certs = mutableListOf<ByteArray>()

            while (currentPos + 12 <= pairsEnd) {
                accessFile.seek(currentPos)
                val pairLen = accessFile.readLong()
                if (pairLen < 4 || pairLen > pairsEnd - currentPos - 8) break

                val pairId = accessFile.readInt()
                val target = when (pairId) {
                    APK_SIGNATURE_SCHEME_V3_BLOCK_ID, APK_SIGNATURE_SCHEME_V31_BLOCK_ID -> v3Certs
                    APK_SIGNATURE_SCHEME_V2_BLOCK_ID -> v2Certs
                    else -> null
                }
                if (target != null) {
                    val dataBytes = ByteArray((pairLen - 4).toInt())
                    accessFile.readFully(dataBytes)
                    target.addAll(parseSigners(ByteBuffer.wrap(dataBytes).order(ByteOrder.LITTLE_ENDIAN)))
                }
                currentPos += 8 + pairLen
            }

            return v3Certs.ifEmpty { v2Certs }
        }
    }

    private fun getLengthPrefixedSlice(buffer: ByteBuffer): ByteBuffer {
        check(buffer.remaining() >= 4) { "Remaining buffer too short: ${buffer.remaining()}" }
        val len = buffer.int
        require(len >= 0) { "Negative length: $len" }
        require(len <= buffer.remaining()) { "Length exceeds remaining buffer: $len > ${buffer.remaining()}" }
        val limit = buffer.limit()
        val position = buffer.position()
        buffer.limit(position + len)
        val slice = buffer.slice().order(ByteOrder.LITTLE_ENDIAN)
        buffer.position(position + len)
        buffer.limit(limit)
        return slice
    }

    private fun readLengthPrefixedByteArray(buffer: ByteBuffer): ByteArray {
        val slice = getLengthPrefixedSlice(buffer)
        val bytes = ByteArray(slice.remaining())
        slice.get(bytes)
        return bytes
    }

    private fun parseSigners(buffer: ByteBuffer): List<ByteArray> {
        val certs = mutableListOf<ByteArray>()
        try {
            val signersSlice = getLengthPrefixedSlice(buffer)
            while (signersSlice.hasRemaining()) {
                val signerSlice = getLengthPrefixedSlice(signersSlice)
                val signedData = getLengthPrefixedSlice(signerSlice)
                // Skip digests
                getLengthPrefixedSlice(signedData)
                // Certificates
                val certificates = getLengthPrefixedSlice(signedData)
                while (certificates.hasRemaining()) {
                    val certBytes = readLengthPrefixedByteArray(certificates)
                    certs.add(certBytes)
                }
            }
        } catch (_: Exception) {
        }
        return certs
    }

    private fun getV1Signatures(apkFile: File): List<ByteArray> {
        val certs = mutableListOf<ByteArray>()
        try {
            java.util.zip.ZipFile(apkFile).use { zip ->
                val entries = zip.entries()
                val certFactory = CertificateFactory.getInstance("X.509")
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val name = entry.name.uppercase()
                    if (name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                        zip.getInputStream(entry).use { stream ->
                            val generated = certFactory.generateCertificates(stream)
                            for (cert in generated) {
                                if (cert is X509Certificate) {
                                    certs.add(cert.encoded)
                                }
                            }
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return certs
    }
}
