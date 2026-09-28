package top.nkbe.nza.data.stream

import java.io.IOException
import java.io.OutputStream
import java.util.zip.CRC32

class CrcOutputStream(
    private val outputStream: OutputStream
) : OutputStream() {

    private val crc32 = CRC32()

    var count: Long = 0
        private set

    val crc: Int
        get() = crc32.value.toInt()

    @Throws(IOException::class)
    override fun write(b: ByteArray, off: Int, len: Int) {
        outputStream.write(b, off, len)
        crc32.update(b, off, len)
        count += len.toLong()
    }

    @Throws(IOException::class)
    override fun write(b: Int) {
        outputStream.write(b)
        crc32.update(b)
        count++
    }

    @Throws(IOException::class)
    override fun close() {
        outputStream.close()
    }
}

