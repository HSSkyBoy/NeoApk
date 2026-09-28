package top.nkbe.nza.data.source

import java.io.IOException
import kotlin.math.max
import kotlin.math.min

class MemoryRandomAccessData(
    private var buffer: ByteArray = ByteArray(0),
    override val name: String = "MemoryData"
) : RandomAccessData {

    private var pos: Long = 0
    private var size: Long = buffer.size.toLong()

    @Throws(IOException::class)
    override fun seek(pos: Long) {
        require(pos >= 0) { "Negative position: $pos" }
        this.pos = pos
    }

    @Throws(IOException::class)
    override fun read(data: ByteArray, off: Int, len: Int): Int {
        if (pos >= size) return -1
        val available = (size - pos).toInt()
        val toRead = min(len, available)
        System.arraycopy(buffer, pos.toInt(), data, off, toRead)
        pos += toRead
        return toRead
    }

    @Throws(IOException::class)
    override fun write(data: ByteArray, off: Int, len: Int) {
        val required = (pos + len).toInt()
        if (required > buffer.size) {
            val newCap = max(buffer.size * 2, required)
            val newBuf = ByteArray(newCap)
            System.arraycopy(buffer, 0, newBuf, 0, size.toInt())
            buffer = newBuf
        }
        System.arraycopy(data, off, buffer, pos.toInt(), len)
        pos += len
        if (pos > size) size = pos
    }

    @Throws(IOException::class)
    override fun length(): Long = size

    @Throws(IOException::class)
    override fun setLength(newLength: Long) {
        require(newLength >= 0) { "Negative length: $newLength" }
        if (newLength > buffer.size) {
            val newBuf = ByteArray(newLength.toInt())
            System.arraycopy(buffer, 0, newBuf, 0, size.toInt())
            buffer = newBuf
        }
        size = newLength
        if (pos > size) pos = size
    }

    @Throws(IOException::class)
    override fun position(): Long = pos

    @Throws(IOException::class)
    override fun sync() {}

    @Throws(IOException::class)
    override fun getAnotherInSameParent(name: String): RandomAccessData {
        return MemoryRandomAccessData(ByteArray(0), name)
    }

    @Throws(IOException::class)
    override fun newSameInstance(): RandomAccessData {
        val copy = ByteArray(size.toInt())
        System.arraycopy(buffer, 0, copy, 0, size.toInt())
        return MemoryRandomAccessData(copy, name)
    }

    @Throws(IOException::class)
    override fun close() {}

    fun toByteArray(): ByteArray {
        val result = ByteArray(size.toInt())
        System.arraycopy(buffer, 0, result, 0, size.toInt())
        return result
    }
}

