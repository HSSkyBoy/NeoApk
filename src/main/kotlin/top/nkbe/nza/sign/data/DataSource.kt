package top.nkbe.nza.sign.data

import top.nkbe.nza.data.buffer.BufferedRandomAccess
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.OutputStream
import java.security.MessageDigest
import kotlin.math.min

interface DataSource {
    fun size(): Long
    fun pos(): Long

    fun remaining(): Long = size() - pos()

    @Throws(IOException::class)
    fun reset()

    @Throws(IOException::class)
    fun copyTo(os: OutputStream, length: Long)

    @Throws(IOException::class)
    fun copyTo(digest: MessageDigest, length: Long) {
        val os = object : OutputStream() {
            override fun write(b: Int) {
                digest.update(b.toByte())
            }

            override fun write(b: ByteArray, off: Int, len: Int) {
                digest.update(b, off, len)
            }
        }
        copyTo(os, length)
    }

    @Throws(IOException::class)
    fun copyTo(accessFile: BufferedRandomAccess, length: Long) {
        val os = object : OutputStream() {
            @Throws(IOException::class)
            override fun write(b: Int) {
                accessFile.write(b)
            }

            @Throws(IOException::class)
            override fun write(b: ByteArray, off: Int, len: Int) {
                accessFile.write(b, off, len)
            }
        }
        copyTo(os, length)
    }

    fun align(align: Int): DataSource = DataSources.align(this, align)

    @Throws(IOException::class)
    fun toMemory(): ByteArrayDataSource {
        val rem = remaining()
        if (rem > Int.MAX_VALUE) {
            throw IOException("Data too large for memory: $rem")
        }
        val baos = ByteArrayOutputStream(rem.toInt())
        copyTo(baos, rem)
        return DataSources.fromData(baos.toByteArray()) as ByteArrayDataSource
    }
}

class ByteArrayDataSource(
    val buffer: ByteArray,
    val start: Int = 0,
    private val _size: Int = buffer.size - start
) : DataSource {

    private var currentPos: Int = 0

    init {
        require(start + _size <= buffer.size) { "start + size > buffer.length" }
    }

    override fun size(): Long = _size.toLong()
    override fun pos(): Long = currentPos.toLong()

    override fun reset() {
        currentPos = 0
    }

    @Throws(IOException::class)
    override fun copyTo(os: OutputStream, length: Long) {
        if (length > remaining()) throw EOFException()
        os.write(buffer, start + currentPos, length.toInt())
        currentPos += length.toInt()
    }
}

class FileDataSource(
    private val randomAccessFile: BufferedRandomAccess,
    private val start: Long,
    private val dataSize: Long
) : DataSource {

    private var currentPos: Long = 0

    private companion object {
        const val COPY_BUFFER_SIZE = 64 * 1024
    }

    override fun size(): Long = dataSize
    override fun pos(): Long = currentPos

    override fun reset() {
        currentPos = 0
    }

    @Throws(IOException::class)
    override fun copyTo(os: OutputStream, length: Long) {
        if (length > remaining()) throw EOFException()
        var remainingBytes = length
        val buf = ByteArray(min(length, COPY_BUFFER_SIZE.toLong()).toInt())
        randomAccessFile.seek(start + currentPos)
        while (remainingBytes > 0) {
            val toRead = min(remainingBytes, buf.size.toLong()).toInt()
            val readLen = randomAccessFile.read(buf, 0, toRead)
            if (readLen == -1) break
            os.write(buf, 0, readLen)
            remainingBytes -= readLen.toLong()
            currentPos += readLen.toLong()
        }
        if (remainingBytes != 0L) {
            throw IllegalStateException("Remaining length: $remainingBytes")
        }
    }
}

class ChainedDataSource(
    private val sources: Array<DataSource>
) : DataSource {

    private var currentIndex: Int = 0
    private var currentSource: DataSource = sources[0]
    private var totalPos: Long = 0
    private val totalSize: Long

    init {
        require(sources.isNotEmpty()) { "Sources cannot be empty" }
        var sum = 0L
        for (s in sources) {
            sum += s.size()
        }
        totalSize = sum
    }

    override fun size(): Long = totalSize
    override fun pos(): Long = totalPos

    @Throws(IOException::class)
    override fun reset() {
        currentIndex = 0
        currentSource = sources[0]
        totalPos = 0
        for (s in sources) {
            s.reset()
        }
    }

    @Throws(IOException::class)
    override fun copyTo(os: OutputStream, length: Long) {
        if (length > remaining()) throw EOFException()
        var remainingBytes = length
        while (remainingBytes > 0) {
            val len = min(remainingBytes, currentSource.remaining())
            currentSource.copyTo(os, len)
            remainingBytes -= len
            totalPos += len
            if (currentSource.remaining() == 0L && currentIndex < sources.size - 1) {
                currentIndex++
                currentSource = sources[currentIndex]
            }
        }
    }
}

object DataSources {
    @JvmStatic
    fun fromFile(randomAccessFile: BufferedRandomAccess, start: Long, size: Long): DataSource =
        FileDataSource(randomAccessFile, start, size)

    @JvmStatic
    fun fromData(data: ByteArray): DataSource =
        ByteArrayDataSource(data, 0, data.size)

    @JvmStatic
    fun fromData(data: ByteArray, start: Int, size: Int): DataSource =
        ByteArrayDataSource(data, start, size)

    @JvmStatic
    fun align(source: DataSource, align: Int): DataSource {
        val size = source.size()
        val overCount = (size % align).toInt()
        if (overCount == 0) return source
        val fillCount = align - overCount
        return link(source, fromData(ByteArray(fillCount)))
    }

    @JvmStatic
    fun link(vararg sources: DataSource): DataSource =
        ChainedDataSource(arrayOf(*sources))

    @JvmStatic
    @Throws(IOException::class)
    fun reset(vararg sources: DataSource) {
        for (source in sources) {
            source.reset()
        }
    }
}

