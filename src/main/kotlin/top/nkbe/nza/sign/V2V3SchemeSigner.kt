package top.nkbe.nza.sign

import top.nkbe.nza.data.buffer.BufferedRandomAccess
import top.nkbe.nza.data.buffer.RandomAccessFactory
import top.nkbe.nza.sign.ByteArrayUtil.intToBytes
import top.nkbe.nza.sign.ByteArrayUtil.readUInt
import top.nkbe.nza.sign.ByteArrayUtil.setUInt
import top.nkbe.nza.sign.data.DataSources
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.cert.CertificateEncodingException
import java.security.cert.X509Certificate
import java.security.interfaces.RSAKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec

object V2V3SchemeSigner {
    private const val ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 0x1000 // 4096
    private const val VERITY_PADDING_BLOCK_ID = 0x42726577
    private const val APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
    private const val APK_SIGNATURE_SCHEME_V3_BLOCK_ID: Int = -0x0fac9740 // 0xf05368c0
    private const val V3_MIN_SDK = 28
    private const val V3_MAX_SDK = Int.MAX_VALUE
    private const val MAX_UINT32 = 0xFFFFFFFFL

    @JvmStatic
    @Throws(Exception::class)
    fun sign(
        file: File,
        signatureKey: SignatureKey,
        enableV2: Boolean = true,
        enableV3: Boolean = true
    ) {
        RandomAccessFactory.from(file, "rw").use { accessFile ->
            sign(accessFile, signatureKey, enableV2, enableV3)
        }
    }

    @JvmStatic
    @Throws(Exception::class)
    fun sign(
        accessFile: BufferedRandomAccess,
        signatureKey: SignatureKey,
        enableV2: Boolean = true,
        enableV3: Boolean = true
    ) {
        require(enableV2 || enableV3) { "At least one of V2 or V3 must be enabled" }

        val publicKey = signatureKey.certificate.publicKey
        var algorithms = getSuggestedSignatureAlgorithms(publicKey)

        val zipBuffer = ZipBuffer(accessFile)

        if (zipBuffer.length() > Int.MAX_VALUE) {
            // Android 15+ VerityBuilder arithmetic overflow workaround for APKs > 2GB
            algorithms = algorithms.filterNot { it is SignatureAlgorithm.BaseVeritySignatureAlgorithm }
        }

        val beforeCentralDir = DataSources
            .fromFile(accessFile, 0, zipBuffer.entriesDataSizeBytes)
            .align(ANDROID_COMMON_PAGE_ALIGNMENT_BYTES)

        val centralDir = DataSources
            .fromFile(accessFile, zipBuffer.centralDirectoryOffset, zipBuffer.centralDirectorySizeBytes)
            .toMemory()

        val eocd = DataSources
            .fromFile(accessFile, zipBuffer.eocdOffset, zipBuffer.length() - zipBuffer.eocdOffset)
            .toMemory()
        val eocdData = eocd.buffer
        val cdOffsetField = eocd.start + 16

        // Digests are computed as if the central directory directly followed the (aligned) entries.
        val dif = zipBuffer.centralDirectoryOffset - beforeCentralDir.size()
        if (dif != 0L) {
            setUInt(readUInt(eocdData, cdOffsetField) - dif, eocdData, cdOffsetField)
        }

        for ((index, algorithm) in algorithms.withIndex()) {
            if (index > 0) {
                DataSources.reset(beforeCentralDir, centralDir, eocd)
            }
            algorithm.computeDigest(beforeCentralDir, centralDir, eocd)
        }

        val certificates = encodeCertificatePart(*signatureKey.certificates)
        val encodedPublicKey = encodePublicKey(publicKey)
        val pairs = ArrayList<ByteArray>(2)

        if (enableV2) {
            // The trailing 4 zero bytes after the additional attributes are ignored by verifiers.
            val signedData = concat(encodeDigestPart(algorithms), certificates, ByteArray(4), ByteArray(4))
            val signers = signSigners(signatureKey, publicKey, algorithms, signedData, ByteArray(0), encodedPublicKey)
            pairs.add(idValuePair(APK_SIGNATURE_SCHEME_V2_BLOCK_ID, signers))
        }

        if (enableV3) {
            val sdkRange = concat(intToBytes(V3_MIN_SDK), intToBytes(V3_MAX_SDK))
            val signedData = concat(encodeDigestPart(algorithms), certificates, sdkRange, ByteArray(4))
            val signers = signSigners(signatureKey, publicKey, algorithms, signedData, sdkRange, encodedPublicKey)
            pairs.add(idValuePair(APK_SIGNATURE_SCHEME_V3_BLOCK_ID, signers))
        }

        val signingBlock = buildSigningBlock(pairs)

        val padSizeBeforeApkSigningBlock = getPaddingSize(
            zipBuffer.entriesDataSizeBytes,
            ANDROID_COMMON_PAGE_ALIGNMENT_BYTES
        )
        accessFile.setLength(zipBuffer.entriesDataSizeBytes)
        accessFile.seek(zipBuffer.entriesDataSizeBytes)
        if (padSizeBeforeApkSigningBlock != 0) {
            accessFile.write(ByteArray(padSizeBeforeApkSigningBlock))
        }
        accessFile.write(signingBlock)

        val centralStart = accessFile.filePointer
        check(centralStart <= MAX_UINT32) { "Central directory offset exceeds 4GB: $centralStart" }
        centralDir.reset()
        centralDir.copyTo(accessFile, centralDir.size())
        setUInt(centralStart, eocdData, cdOffsetField)
        eocd.reset()
        eocd.copyTo(accessFile, eocd.size())
    }

    /** Signs [signedData] with every algorithm and returns the length-prefixed signers sequence. */
    private fun signSigners(
        signatureKey: SignatureKey,
        publicKey: PublicKey,
        algorithms: List<SignatureAlgorithm>,
        signedData: ByteArray,
        sdkRange: ByteArray,
        encodedPublicKey: ByteArray
    ): ByteArray {
        for (algorithm in algorithms) {
            algorithm.computeSignature(signatureKey.privateKey, publicKey, signedData)
        }
        val signer = concat(
            lengthPrefixed(signedData),
            sdkRange,
            lengthPrefixed(encodeSignature(algorithms)),
            lengthPrefixed(encodedPublicKey)
        )
        return lengthPrefixed(lengthPrefixed(signer))
    }

    private fun idValuePair(id: Int, value: ByteArray): ByteArray =
        ByteBuffer.allocate(8 + 4 + value.size).order(ByteOrder.LITTLE_ENDIAN)
            .putLong((4 + value.size).toLong())
            .putInt(id)
            .put(value)
            .array()

    /** Layout: size(8) | pairs | [padding pair] | size(8) | magic(16), padded so the block ends on a 4KB boundary. */
    private fun buildSigningBlock(pairs: List<ByteArray>): ByteArray {
        val unpaddedSize = 8 + pairs.sumOf { it.size } + 8 + 16
        var padding = 0
        if (unpaddedSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES != 0) {
            padding = ANDROID_COMMON_PAGE_ALIGNMENT_BYTES - unpaddedSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES
            if (padding < 12) padding += ANDROID_COMMON_PAGE_ALIGNMENT_BYTES
        }
        val totalSize = unpaddedSize + padding
        val blockSizeFieldValue = totalSize - 8L

        val buffer = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putLong(blockSizeFieldValue)
        pairs.forEach { buffer.put(it) }
        if (padding > 0) {
            buffer.putLong((padding - 8).toLong())
            buffer.putInt(VERITY_PADDING_BLOCK_ID)
            buffer.position(buffer.position() + padding - 12)
        }
        buffer.putLong(blockSizeFieldValue)
        buffer.putLong(ZipBuffer.APK_SIG_BLOCK_MAGIC_LO)
        buffer.putLong(ZipBuffer.APK_SIG_BLOCK_MAGIC_HI)
        check(!buffer.hasRemaining()) { "Signing block size mismatch: ${buffer.remaining()} bytes unwritten" }
        return buffer.array()
    }

    private fun concat(vararg parts: ByteArray): ByteArray {
        val result = ByteArray(parts.sumOf { it.size })
        var pos = 0
        for (part in parts) {
            System.arraycopy(part, 0, result, pos, part.size)
            pos += part.size
        }
        return result
    }

    private fun lengthPrefixed(body: ByteArray): ByteArray = concat(intToBytes(body.size), body)

    private fun encodeDigestPart(algorithms: Collection<SignatureAlgorithm>): ByteArray =
        lengthPrefixed(concat(*algorithms.map { encodeIdWithPrefixLengthData(it.id, it.digest!!) }.toTypedArray()))

    @Throws(CertificateEncodingException::class)
    private fun encodeCertificatePart(vararg certificates: X509Certificate): ByteArray =
        lengthPrefixed(concat(*certificates.map { lengthPrefixed(it.encoded) }.toTypedArray()))

    private fun encodeSignature(algorithms: Collection<SignatureAlgorithm>): ByteArray =
        concat(*algorithms.map { encodeIdWithPrefixLengthData(it.id, it.signature!!) }.toTypedArray())

    private fun encodeIdWithPrefixLengthData(id: Int, data: ByteArray): ByteArray =
        lengthPrefixed(concat(intToBytes(id), lengthPrefixed(data)))

    private fun getPaddingSize(length: Long, align: Int): Int {
        val overCount = (length % align).toInt()
        return if (overCount == 0) 0 else align - overCount
    }

    @Throws(InvalidKeyException::class)
    private fun getSuggestedSignatureAlgorithms(signingKey: PublicKey): List<SignatureAlgorithm> {
        val keyAlgorithm = signingKey.algorithm
        return when {
            "RSA".equals(keyAlgorithm, ignoreCase = true) -> {
                val modulusLengthBits = (signingKey as RSAKey).modulus.bitLength()
                if (modulusLengthBits <= 3072) {
                    listOf(
                        SignatureAlgorithm.rsaPkcs1V15WithSha256(),
                        SignatureAlgorithm.verityRsaPkcs1V15WithSha256()
                    )
                } else {
                    listOf(SignatureAlgorithm.rsaPkcs1V15WithSha512())
                }
            }
            "DSA".equals(keyAlgorithm, ignoreCase = true) -> {
                listOf(
                    SignatureAlgorithm.dsaWithSha256(),
                    SignatureAlgorithm.verityDsaWithSha256()
                )
            }
            "EC".equals(keyAlgorithm, ignoreCase = true) -> {
                listOf(
                    SignatureAlgorithm.ecdsaWithSha256(),
                    SignatureAlgorithm.verityEcdsaWithSha256()
                )
            }
            else -> throw InvalidKeyException("Unsupported key algorithm: $keyAlgorithm")
        }
    }

    @Throws(InvalidKeyException::class, NoSuchAlgorithmException::class)
    private fun encodePublicKey(publicKey: PublicKey): ByteArray {
        val encoded: ByteArray? = try {
            KeyFactory.getInstance(publicKey.algorithm)
                .getKeySpec(publicKey, X509EncodedKeySpec::class.java)
                .encoded
        } catch (e: InvalidKeySpecException) {
            throw InvalidKeyException(
                "Failed to obtain X.509 encoded form of public key $publicKey of class ${publicKey.javaClass.name}",
                e
            )
        }
        if (encoded == null || encoded.isEmpty()) {
            throw InvalidKeyException(
                "Failed to obtain X.509 encoded form of public key $publicKey of class ${publicKey.javaClass.name}"
            )
        }
        return encoded
    }
}
