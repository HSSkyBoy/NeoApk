package top.nkbe.nza.sign

import top.nkbe.nza.sign.data.DataSource
import java.io.IOException
import java.io.OutputStream
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.HashMap
import kotlin.math.min

abstract class SignatureAlgorithm {

    companion object {
        private const val ONE_MB = 1024 * 1024
        private val MAP = HashMap<Int, () -> SignatureAlgorithm>()

        init {
            MAP[0x0101] = { rsaPssWithSha256() }
            MAP[0x0102] = { rsaPssWithSha512() }
            MAP[0x0103] = { rsaPkcs1V15WithSha256() }
            MAP[0x0104] = { rsaPkcs1V15WithSha512() }
            MAP[0x0201] = { ecdsaWithSha256() }
            MAP[0x0202] = { ecdsaWithSha512() }
            MAP[0x0301] = { dsaWithSha256() }
            MAP[0x0421] = { verityRsaPkcs1V15WithSha256() }
            MAP[0x0423] = { verityEcdsaWithSha256() }
            MAP[0x0425] = { verityDsaWithSha256() }
        }

        fun isAlgorithmIdSupported(id: Int): Boolean = MAP.containsKey(id)

        fun getByAlgorithmId(id: Int): SignatureAlgorithm {
            val supplier = MAP[id] ?: throw RuntimeException("Unsupported signature algorithm id: 0x${Integer.toHexString(id)}")
            return supplier()
        }

        fun findByAlgorithmId(id: Int): SignatureAlgorithm? = MAP[id]?.invoke()

        fun rsaPssWithSha256(): SignatureAlgorithm = BaseSignatureAlgorithm(
            0x0101, "SHA-256", "RSA", "SHA256withRSA/PSS",
            PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 256 / 8, 1)
        )

        fun rsaPssWithSha512(): SignatureAlgorithm = BaseSignatureAlgorithm(
            0x0102, "SHA-512", "RSA", "SHA512withRSA/PSS",
            PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 512 / 8, 1)
        )

        fun rsaPkcs1V15WithSha256(): SignatureAlgorithm = BaseSignatureAlgorithm(
            0x0103, "SHA-256", "RSA", "SHA256withRSA", null
        )

        fun rsaPkcs1V15WithSha512(): SignatureAlgorithm = BaseSignatureAlgorithm(
            0x0104, "SHA-512", "RSA", "SHA512withRSA", null
        )

        fun ecdsaWithSha256(): SignatureAlgorithm = BaseSignatureAlgorithm(
            0x0201, "SHA-256", "EC", "SHA256withECDSA", null
        )

        fun ecdsaWithSha512(): SignatureAlgorithm = BaseSignatureAlgorithm(
            0x0202, "SHA-512", "EC", "SHA512withECDSA", null
        )

        fun dsaWithSha256(): SignatureAlgorithm = BaseSignatureAlgorithm(
            0x0301, "SHA-256", "DSA", "SHA256withDSA", null
        )

        fun verityRsaPkcs1V15WithSha256(): SignatureAlgorithm = BaseVeritySignatureAlgorithm(
            0x0421, "RSA", "SHA256withRSA", null
        )

        fun verityEcdsaWithSha256(): SignatureAlgorithm = BaseVeritySignatureAlgorithm(
            0x0423, "EC", "SHA256withECDSA", null
        )

        fun verityDsaWithSha256(): SignatureAlgorithm = BaseVeritySignatureAlgorithm(
            0x0425, "DSA", "SHA256withDSA", null
        )

        @Throws(IOException::class)
        private fun updateChunkContentDigest(
            contentDigest: MessageDigest,
            dataSource: DataSource,
            output: OutputStream
        ) {
            val chunkCount = getChunkCount(dataSource.size())
            val chunkContentPrefix = ByteArray(5)
            chunkContentPrefix[0] = 0xa5.toByte()

            for (i in 0 until chunkCount) {
                val start = dataSource.pos()
                val end = min(start + ONE_MB, dataSource.size())
                val chunkSize = (end - start).toInt()
                ByteArrayUtil.setInt(chunkSize, chunkContentPrefix, 1)

                contentDigest.update(chunkContentPrefix)
                dataSource.copyTo(contentDigest, chunkSize.toLong())

                val digest = contentDigest.digest()
                output.write(digest)
            }
        }

        private fun getChunkCount(inputSize: Long): Int =
            ((inputSize + ONE_MB - 1) / ONE_MB).toInt()
    }

    var digest: ByteArray? = null
        protected set
    var signature: ByteArray? = null
        protected set

    abstract val id: Int
    abstract val minSdkVersion: Int
    abstract val keyAlgorithm: String
    abstract val signatureAlgorithm: String
    abstract val signatureAlgorithmParams: AlgorithmParameterSpec?

    @Throws(Exception::class)
    abstract fun computeDigest(
        beforeCentralDir: DataSource,
        centralDir: DataSource,
        eocd: DataSource
    )

    @Throws(Exception::class)
    fun verifySignature(publicKey: PublicKey, signedData: ByteArray, signatureBytes: ByteArray): Boolean {
        val jcaAlgorithm = signatureAlgorithm
        val params = signatureAlgorithmParams
        try {
            val sig = Signature.getInstance(jcaAlgorithm)
            sig.initVerify(publicKey)
            if (params != null) {
                sig.setParameter(params)
            }
            sig.update(signedData)
            return sig.verify(signatureBytes)
        } catch (e: InvalidKeyException) {
            throw InvalidKeyException("Failed to verify generated $jcaAlgorithm signature using public key", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw SignatureException("Failed to verify generated $jcaAlgorithm signature using public key", e)
        } catch (e: SignatureException) {
            throw SignatureException("Failed to verify generated $jcaAlgorithm signature using public key", e)
        }
    }

    @Throws(Exception::class)
    fun computeSignature(privateKey: PrivateKey, publicKey: PublicKey, signedData: ByteArray) {
        val jcaAlgorithm = signatureAlgorithm
        val params = signatureAlgorithmParams
        val signatureBytes: ByteArray
        try {
            val sig = Signature.getInstance(jcaAlgorithm)
            sig.initSign(privateKey)
            if (params != null) {
                sig.setParameter(params)
            }
            sig.update(signedData)
            signatureBytes = sig.sign()
        } catch (e: InvalidKeyException) {
            throw InvalidKeyException("Failed to sign using $jcaAlgorithm", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw SignatureException("Failed to sign using $jcaAlgorithm", e)
        } catch (e: SignatureException) {
            throw SignatureException("Failed to sign using $jcaAlgorithm", e)
        }

        try {
            val sig = Signature.getInstance(jcaAlgorithm)
            sig.initVerify(publicKey)
            if (params != null) {
                sig.setParameter(params)
            }
            sig.update(signedData)
            if (!sig.verify(signatureBytes)) {
                throw SignatureException("Failed to verify generated $jcaAlgorithm signature using public key")
            }
        } catch (e: InvalidKeyException) {
            throw InvalidKeyException("Failed to verify generated $jcaAlgorithm signature using public key", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw SignatureException("Failed to verify generated $jcaAlgorithm signature using public key", e)
        } catch (e: SignatureException) {
            throw SignatureException("Failed to verify generated $jcaAlgorithm signature using public key", e)
        }
        signature = signatureBytes
    }

    class BaseSignatureAlgorithm(
        override val id: Int,
        val digestAlgorithm: String,
        override val keyAlgorithm: String,
        override val signatureAlgorithm: String,
        override val signatureAlgorithmParams: AlgorithmParameterSpec?
    ) : SignatureAlgorithm() {

        override val minSdkVersion: Int
            get() = 24

        @Throws(Exception::class)
        override fun computeDigest(
            beforeCentralDir: DataSource,
            centralDir: DataSource,
            eocd: DataSource
        ) {
            val md1 = MessageDigest.getInstance(digestAlgorithm)
            val md2 = MessageDigest.getInstance(digestAlgorithm)
            val totalChunkSize = getChunkCount(beforeCentralDir.size()) +
                    getChunkCount(centralDir.size()) +
                    getChunkCount(eocd.size())

            val output = object : OutputStream() {
                override fun write(b: Int) {
                    md2.update(b.toByte())
                }

                override fun write(b: ByteArray, off: Int, len: Int) {
                    md2.update(b, off, len)
                }
            }

            val prefix = ByteArray(5)
            prefix[0] = 0x5a.toByte()
            ByteArrayUtil.setInt(totalChunkSize, prefix, 1)
            output.write(prefix)

            updateChunkContentDigest(md1, beforeCentralDir, output)
            updateChunkContentDigest(md1, centralDir, output)
            updateChunkContentDigest(md1, eocd, output)

            digest = md2.digest()
        }
    }

    class BaseVeritySignatureAlgorithm(
        override val id: Int,
        override val keyAlgorithm: String,
        override val signatureAlgorithm: String,
        override val signatureAlgorithmParams: AlgorithmParameterSpec?
    ) : SignatureAlgorithm() {

        override val minSdkVersion: Int
            get() = 28

        @Throws(Exception::class)
        override fun computeDigest(
            beforeCentralDir: DataSource,
            centralDir: DataSource,
            eocd: DataSource
        ) {
            val builder = VerityTreeBuilder(ByteArray(8))
            val rootHash = builder.generateVerityTreeRootHash(beforeCentralDir, centralDir, eocd)
            val result = ByteArray(rootHash.size + 8)
            System.arraycopy(rootHash, 0, result, 0, rootHash.size)
            val totalSize = beforeCentralDir.size() + centralDir.size() + eocd.size()
            ByteArrayUtil.setLong(totalSize, result, rootHash.size)
            digest = result
        }
    }
}

