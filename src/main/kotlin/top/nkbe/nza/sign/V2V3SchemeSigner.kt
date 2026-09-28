package top.nkbe.nza.sign

import top.nkbe.nza.data.buffer.BufferedRandomAccess
import top.nkbe.nza.data.buffer.RandomAccessFactory
import top.nkbe.nza.sign.ByteArrayUtil.intToBytes
import top.nkbe.nza.sign.ByteArrayUtil.readUInt
import top.nkbe.nza.sign.ByteArrayUtil.setInt
import top.nkbe.nza.sign.ByteArrayUtil.setLong
import top.nkbe.nza.sign.ByteArrayUtil.setUInt
import top.nkbe.nza.sign.data.ByteArrayDataSource
import top.nkbe.nza.sign.data.DataSource
import top.nkbe.nza.sign.data.DataSources
import java.io.File
import java.security.InvalidKeyException
import java.security.KeyFactory
import java.security.NoSuchAlgorithmException
import java.security.PublicKey
import java.security.cert.CertificateEncodingException
import java.security.cert.X509Certificate
import java.security.interfaces.RSAKey
import java.security.spec.InvalidKeySpecException
import java.security.spec.X509EncodedKeySpec
import java.util.ArrayList

object V2V3SchemeSigner {
    private const val ANDROID_COMMON_PAGE_ALIGNMENT_BYTES = 0x1000 // 4096
    private const val VERITY_PADDING_BLOCK_ID = 0x42726577
    private const val APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
    private const val APK_SIGNATURE_SCHEME_V3_BLOCK_ID: Int = -0x0fac9740 // 0xf05368c0

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
        if (!enableV2 && !enableV3) {
            throw IllegalArgumentException("At least one of V2 or V3 must be enabled")
        }

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

        var start = zipBuffer.centralDirectoryOffset
        var size = zipBuffer.centralDirectorySizeBytes
        val centralDir = DataSources.fromFile(accessFile, start, size).toMemory()

        start = zipBuffer.eocdOffset
        size = zipBuffer.length() - start
        val eocd = DataSources.fromFile(accessFile, start, size).toMemory()
        val dif = (zipBuffer.centralDirectoryOffset - beforeCentralDir.size()).toInt()
        if (dif != 0) {
            val eocdData = eocd.buffer
            val valueOffset = eocd.start + 16
            var cdOffset = readUInt(eocdData, valueOffset)
            cdOffset -= dif.toLong()
            setUInt(cdOffset, eocdData, valueOffset)
        }

        var reset = false
        for (algorithm in algorithms) {
            if (reset) {
                DataSources.reset(beforeCentralDir, centralDir, eocd)
            }
            algorithm.computeDigest(beforeCentralDir, centralDir, eocd)
            reset = true
        }

        var apkSignatureSchemeV2Block: ByteArray? = null
        var apkSignatureSchemeV3Block: ByteArray? = null

        if (enableV2) {
            val v2SignedData = concat(
                encodeDigestPart(algorithms),
                encodeCertificatePart(*signatureKey.certificates),
                encodeAdditionalPart(),
                ByteArray(4)
            )
            for (algorithm in algorithms) {
                algorithm.computeSignature(signatureKey.privateKey, publicKey, v2SignedData)
            }
            val signature = encodeSignature(algorithms)
            val encodedPublicKey = encodePublicKey(publicKey)
            val v2Length = v2SignedData.size + signature.size + encodedPublicKey.size + 12
            apkSignatureSchemeV2Block = concat(
                intToBytes(v2Length + 4),
                intToBytes(v2Length),
                intToBytes(v2SignedData.size),
                v2SignedData,
                intToBytes(signature.size),
                signature,
                intToBytes(encodedPublicKey.size),
                encodedPublicKey
            )
        }

        if (enableV3) {
            val v3SignedData = concat(
                encodeDigestPart(algorithms),
                encodeCertificatePart(*signatureKey.certificates),
                intToBytes(28), // minSDK
                intToBytes(Int.MAX_VALUE), // maxSDK
                encodeAdditionalPart()
            )
            for (algorithm in algorithms) {
                algorithm.computeSignature(signatureKey.privateKey, publicKey, v3SignedData)
            }
            val signature = encodeSignature(algorithms)
            val encodedPublicKey = encodePublicKey(publicKey)
            val v3Length = v3SignedData.size + signature.size + encodedPublicKey.size + 20
            apkSignatureSchemeV3Block = concat(
                intToBytes(v3Length + 4),
                intToBytes(v3Length),
                intToBytes(v3SignedData.size),
                v3SignedData,
                intToBytes(28), // minSDK
                intToBytes(Int.MAX_VALUE), // maxSDK
                intToBytes(signature.size),
                signature,
                intToBytes(encodedPublicKey.size),
                encodedPublicKey
            )
        }

        val v2BlocksSize = if (!enableV2 || apkSignatureSchemeV2Block == null) 0 else 8 + 4 + apkSignatureSchemeV2Block.size
        val v3BlocksSize = if (!enableV3 || apkSignatureSchemeV3Block == null) 0 else 8 + 4 + apkSignatureSchemeV3Block.size
        var resultSize = 8 + v2BlocksSize + v3BlocksSize + 8 + 16

        var paddingPair: ByteArray? = null
        if (resultSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES != 0) {
            var padding = ANDROID_COMMON_PAGE_ALIGNMENT_BYTES -
                    (resultSize % ANDROID_COMMON_PAGE_ALIGNMENT_BYTES)
            if (padding < 12) {
                padding += ANDROID_COMMON_PAGE_ALIGNMENT_BYTES
            }
            paddingPair = ByteArray(padding)
            setLong((padding - 8).toLong(), paddingPair, 0)
            setInt(VERITY_PADDING_BLOCK_ID, paddingPair, 8)
            resultSize += padding
        }

        val result = ByteArray(resultSize)
        val blockSizeFieldValue = resultSize - 8L
        var pos = 0

        setLong(blockSizeFieldValue, result, pos)
        pos += 8

        if (enableV2 && apkSignatureSchemeV2Block != null) {
            setLong((4 + apkSignatureSchemeV2Block.size).toLong(), result, pos)
            pos += 8
            setInt(APK_SIGNATURE_SCHEME_V2_BLOCK_ID, result, pos)
            pos += 4
            System.arraycopy(apkSignatureSchemeV2Block, 0, result, pos, apkSignatureSchemeV2Block.size)
            pos += apkSignatureSchemeV2Block.size
        }

        if (enableV3 && apkSignatureSchemeV3Block != null) {
            setLong((4 + apkSignatureSchemeV3Block.size).toLong(), result, pos)
            pos += 8
            setInt(APK_SIGNATURE_SCHEME_V3_BLOCK_ID, result, pos)
            pos += 4
            System.arraycopy(apkSignatureSchemeV3Block, 0, result, pos, apkSignatureSchemeV3Block.size)
            pos += apkSignatureSchemeV3Block.size
        }

        if (paddingPair != null) {
            System.arraycopy(paddingPair, 0, result, pos, paddingPair.size)
            pos += paddingPair.size
        }

        setLong(blockSizeFieldValue, result, pos)
        pos += 8

        setLong(ZipBuffer.APK_SIG_BLOCK_MAGIC_LO, result, pos)
        pos += 8

        setLong(ZipBuffer.APK_SIG_BLOCK_MAGIC_HI, result, pos)
        pos += 8

        check(pos == resultSize) { "Signing block size mismatch: $pos != $resultSize" }

        val padSizeBeforeApkSigningBlock = getPaddingSize(
            zipBuffer.entriesDataSizeBytes,
            ANDROID_COMMON_PAGE_ALIGNMENT_BYTES
        )
        accessFile.setLength(zipBuffer.entriesDataSizeBytes)
        accessFile.seek(zipBuffer.entriesDataSizeBytes)
        if (padSizeBeforeApkSigningBlock != 0) {
            accessFile.write(ByteArray(padSizeBeforeApkSigningBlock))
        }
        accessFile.write(result)
        val centralStart = accessFile.filePointer.toInt()
        centralDir.reset()
        centralDir.copyTo(accessFile, centralDir.size())
        val eocdData = eocd.buffer
        val valueOffset = eocd.start + 16
        setInt(centralStart, eocdData, valueOffset)
        eocd.reset()
        eocd.copyTo(accessFile, eocd.size())
    }

    private fun concat(vararg sequence: ByteArray): ByteArray {
        var payloadSize = 0
        for (element in sequence) {
            payloadSize += element.size
        }
        val result = ByteArray(payloadSize)
        var pos = 0
        for (element in sequence) {
            System.arraycopy(element, 0, result, pos, element.size)
            pos += element.size
        }
        return result
    }

    private fun encodeDigestPart(algorithms: Collection<SignatureAlgorithm>): ByteArray {
        val digests = ArrayList<ByteArray>(algorithms.size)
        var length = 4
        for (algorithm in algorithms) {
            val data = encodeIdWithPrefixLengthData(algorithm.id, algorithm.digest!!)
            length += data.size
            digests.add(data)
        }
        val result = ByteArray(length)
        setInt(length - 4, result, 0)
        var pos = 4
        for (digest in digests) {
            System.arraycopy(digest, 0, result, pos, digest.size)
            pos += digest.size
        }
        return result
    }

    @Throws(CertificateEncodingException::class)
    private fun encodeCertificatePart(vararg certificates: X509Certificate): ByteArray {
        val encodes = ArrayList<ByteArray>(certificates.size)
        var length = 4
        for (certificate in certificates) {
            val data = certificate.encoded
            length += 4 + data.size
            encodes.add(data)
        }
        val result = ByteArray(length)
        setInt(length - 4, result, 0)
        var pos = 4
        for (encode in encodes) {
            setInt(encode.size, result, pos)
            pos += 4
            System.arraycopy(encode, 0, result, pos, encode.size)
            pos += encode.size
        }
        return result
    }

    private fun encodeSignature(algorithms: Collection<SignatureAlgorithm>): ByteArray {
        val digests = ArrayList<ByteArray>(algorithms.size)
        var length = 0
        for (algorithm in algorithms) {
            val data = encodeIdWithPrefixLengthData(algorithm.id, algorithm.signature!!)
            length += data.size
            digests.add(data)
        }
        val result = ByteArray(length)
        var pos = 0
        for (digest in digests) {
            System.arraycopy(digest, 0, result, pos, digest.size)
            pos += digest.size
        }
        return result
    }

    private fun encodeAdditionalPart(): ByteArray {
        return ByteArray(4)
    }

    private fun encodeIdWithPrefixLengthData(id: Int, digest: ByteArray): ByteArray {
        val result = ByteArray(12 + digest.size)
        setInt(digest.size + 8, result, 0)
        setInt(id, result, 4)
        setInt(digest.size, result, 8)
        System.arraycopy(digest, 0, result, 12, digest.size)
        return result
    }

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
        val encodedPublicKey: ByteArray? = try {
            KeyFactory.getInstance(publicKey.algorithm)
                .getKeySpec(publicKey, X509EncodedKeySpec::class.java)
                .encoded
        } catch (e: InvalidKeySpecException) {
            throw InvalidKeyException(
                "Failed to obtain X.509 encoded form of public key $publicKey of class ${publicKey.javaClass.name}",
                e
            )
        }
        if (encodedPublicKey == null || encodedPublicKey.isEmpty()) {
            throw InvalidKeyException(
                "Failed to obtain X.509 encoded form of public key $publicKey of class ${publicKey.javaClass.name}"
            )
        }
        return encodedPublicKey
    }
}

