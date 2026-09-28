package top.nkbe.nza.sign

import top.nkbe.nza.sign.data.DataSink
import top.nkbe.nza.sign.data.DataSinks
import top.nkbe.nza.sign.data.DataSource
import top.nkbe.nza.sign.data.DataSources
import java.io.IOException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.ArrayList

class VerityTreeBuilder(private val mSalt: ByteArray?) {

    companion object {
        private const val CHUNK_SIZE = 4096
        private const val JCA_ALGORITHM = "SHA-256"

        private fun divideRoundup(dividend: Long): Long {
            return (dividend + CHUNK_SIZE - 1) / CHUNK_SIZE
        }

        private fun toIntExact(value: Long): Int {
            if (value.toInt().toLong() != value) {
                throw ArithmeticException("integer overflow")
            }
            return value.toInt()
        }

        private fun calculateLevelOffset(dataSize: Long, digestSize: Int): IntArray {
            var currentDataSize = dataSize
            val levelSize = ArrayList<Long>()
            while (true) {
                val chunkCount = divideRoundup(currentDataSize)
                val size = CHUNK_SIZE * divideRoundup(chunkCount * digestSize)
                levelSize.add(size)
                if (chunkCount * digestSize <= CHUNK_SIZE) {
                    break
                }
                currentDataSize = chunkCount * digestSize
            }

            val levelOffset = IntArray(levelSize.size + 1)
            levelOffset[0] = 0
            for (i in levelSize.indices) {
                levelOffset[i + 1] = levelOffset[i] + toIntExact(levelSize[levelSize.size - i - 1])
            }
            return levelOffset
        }
    }

    private val mMd: MessageDigest = MessageDigest.getInstance(JCA_ALGORITHM)

    @Throws(IOException::class)
    fun generateVerityTreeRootHash(
        beforeApkSigningBlock: DataSource,
        centralDir: DataSource,
        eocd: DataSource
    ): ByteArray {
        if (beforeApkSigningBlock.size() % CHUNK_SIZE != 0L) {
            throw IllegalStateException(
                "APK Signing Block size not a multiple of $CHUNK_SIZE: ${beforeApkSigningBlock.size()}"
            )
        }
        return generateVerityTreeRootHash(DataSources.link(beforeApkSigningBlock, centralDir, eocd))
    }

    @Throws(IOException::class)
    private fun generateVerityTreeRootHash(fileSource: DataSource): ByteArray {
        val digestSize = mMd.digestLength
        val levelOffset = calculateLevelOffset(fileSource.size(), digestSize)
        val verityBuffer = ByteArray(levelOffset[levelOffset.size - 1])

        for (i in levelOffset.size - 2 downTo 0) {
            val middleBufferSink = DataSinks.fromData(verityBuffer, levelOffset[i], levelOffset[i + 1])
            val src: DataSource = if (i == levelOffset.size - 2) {
                fileSource
            } else {
                val start = levelOffset[i + 1]
                val end = levelOffset[i + 2]
                DataSources.fromData(verityBuffer, start, end - start)
            }
            digestDataByChunks(src, middleBufferSink)

            val totalOutput = divideRoundup(src.size()) * digestSize
            val incomplete = (totalOutput % CHUNK_SIZE).toInt()
            if (incomplete > 0) {
                val padding = ByteArray(CHUNK_SIZE - incomplete)
                middleBufferSink.consume(padding, 0, padding.size)
            }
        }

        return saltedDigest(verityBuffer)
    }

    @Throws(IOException::class)
    private fun digestDataByChunks(dataSource: DataSource, dataSink: DataSink) {
        val alignedSource = dataSource.align(CHUNK_SIZE)
        val size = alignedSource.size()
        var offset = 0L
        while (offset + CHUNK_SIZE <= size) {
            val hash = saltedDigest(alignedSource)
            dataSink.consume(hash, 0, hash.size)
            offset += CHUNK_SIZE
        }

        val remaining = (size % CHUNK_SIZE).toInt()
        if (remaining > 0) {
            throw IllegalStateException("Remaining: $remaining")
        }
    }

    @Throws(IOException::class)
    private fun saltedDigest(source: DataSource): ByteArray {
        mMd.reset()
        if (mSalt != null) {
            mMd.update(mSalt)
        }
        source.copyTo(mMd, CHUNK_SIZE.toLong())
        return mMd.digest()
    }

    private fun saltedDigest(data: ByteArray): ByteArray {
        mMd.reset()
        if (mSalt != null) {
            mMd.update(mSalt)
        }
        mMd.update(data, 0, CHUNK_SIZE)
        return mMd.digest()
    }
}

