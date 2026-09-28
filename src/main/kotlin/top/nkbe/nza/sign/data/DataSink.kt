package top.nkbe.nza.sign.data

import java.io.EOFException
import java.io.IOException

interface DataSink {
    @Throws(IOException::class)
    fun consume(buf: ByteArray, offset: Int, length: Int)
}

class ByteArrayDataSink(
    private val data: ByteArray,
    private var pos: Int,
    private val limit: Int
) : DataSink {

    @Throws(IOException::class)
    override fun consume(buf: ByteArray, offset: Int, length: Int) {
        if (pos + length > limit) {
            throw EOFException()
        }
        System.arraycopy(buf, offset, data, pos, length)
        pos += length
    }
}

object DataSinks {
    @JvmStatic
    fun fromData(data: ByteArray): DataSink =
        ByteArrayDataSink(data, 0, data.size)

    @JvmStatic
    fun fromData(data: ByteArray, position: Int, limit: Int): DataSink =
        ByteArrayDataSink(data, position, limit)
}

