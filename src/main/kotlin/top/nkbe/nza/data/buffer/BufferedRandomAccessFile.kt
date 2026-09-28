package top.nkbe.nza.data.buffer

import top.nkbe.nza.data.source.RandomAccessData
import java.io.EOFException
import java.io.IOException
import java.util.Arrays
import kotlin.math.max
import kotlin.math.min

class BufferedRandomAccessFile(
    val randomAccessData: RandomAccessData
) : BufferedRandomAccess {

    companion object {
        private const val LOG_BUFF_SZ = 17 // 128KB buffer
        private const val BUFF_SZ = 1 shl LOG_BUFF_SZ
        private const val BUFF_MASK = -(BUFF_SZ.toLong())
    }

    private var dirty = false
    private var closed = false
    private var curr: Long = 0
    private var lo: Long = 0
    private var hi: Long = 0
    private var buff: ByteArray = ByteArray(BUFF_SZ)
    private var maxHi: Long = BUFF_SZ.toLong()
    private var hitEOF = false
    private var diskPos: Long = 0
    private var randomAccessDataLength: Long = -1

    init {
        dirty = false
        closed = false
        lo = 0
        curr = 0
        hi = 0
        buff = ByteArray(BUFF_SZ)
        maxHi = BUFF_SZ.toLong()
        hitEOF = false
        diskPos = 0
    }

    @Throws(IOException::class)
    override fun write(value: Int) {
        if (curr >= hi) {
            if (hitEOF && hi < maxHi) {
                hi++
            } else {
                seek(curr)
                if (curr == hi) {
                    hi++
                }
            }
        }
        buff[(curr - lo).toInt()] = value.toByte()
        curr++
        dirty = true
    }

    @Throws(IOException::class)
    override fun write(data: ByteArray, off: Int, len: Int) {
        var currentOff = off
        var currentLen = len
        while (currentLen > 0) {
            val n = writeAtMost(data, currentOff, currentLen)
            currentOff += n
            currentLen -= n
            dirty = true
        }
    }

    @Throws(IOException::class)
    override fun read(): Int {
        if (curr >= hi) {
            if (hitEOF) return -1
            seek(curr)
            if (curr == hi) return -1
        }
        val res = buff[(curr - lo).toInt()]
        curr++
        return res.toInt() and 0xFF
    }

    @Throws(IOException::class)
    override fun read(data: ByteArray, off: Int, len: Int): Int {
        var targetLen = len
        if (curr >= hi) {
            if (hitEOF) return -1
            seek(curr)
            if (curr == hi) return -1
        }
        targetLen = min(targetLen, (hi - curr).toInt())
        val buffOff = (curr - lo).toInt()
        System.arraycopy(buff, buffOff, data, off, targetLen)
        curr += targetLen
        return targetLen
    }

    @Throws(IOException::class)
    override fun readFully(data: ByteArray, off: Int, len: Int) {
        var n = 0
        do {
            val count = read(data, off + n, len - n)
            if (count < 0) throw EOFException()
            n += count
        } while (n < len)
    }

    @Throws(IOException::class)
    override fun length(): Long {
        return max(curr, getRandomAccessDataLength())
    }

    @Throws(IOException::class)
    private fun getRandomAccessDataLength(): Long {
        if (randomAccessDataLength == -1L) {
            randomAccessDataLength = randomAccessData.length()
        }
        return randomAccessDataLength
    }

    @Throws(IOException::class)
    override fun setLength(newLength: Long) {
        flushBuffer()
        randomAccessData.setLength(newLength)
        randomAccessDataLength = newLength
        if (curr > newLength) {
            curr = newLength
        }
        if (diskPos > newLength) {
            randomAccessData.seek(newLength)
            diskPos = newLength
        }
        lo = 0
        hi = 0
        seek(curr)
    }

    @Throws(IOException::class)
    override fun seek(pos: Long) {
        if (pos >= hi || pos < lo) {
            flushBuffer()
            lo = pos and BUFF_MASK
            maxHi = lo + buff.size.toLong()
            if (diskPos != lo) {
                randomAccessData.seek(lo)
                diskPos = lo
            }
            val n = fillBuffer()
            hi = lo + n.toLong()
        } else {
            if (pos < curr) {
                flushBuffer()
            }
        }
        curr = pos
    }

    @Throws(IOException::class)
    override fun skipBytes(n: Int): Int {
        if (n <= 0) return 0
        val pos = filePointer
        val len = length()
        var newpos = pos + n
        if (newpos > len) {
            newpos = len
        }
        seek(newpos)
        return (newpos - pos).toInt()
    }

    override val filePointer: Long
        get() = curr

    override val name: String
        get() = randomAccessData.name

    @Throws(IOException::class)
    override fun getAnotherInSameParent(name: String): BufferedRandomAccess {
        return BufferedRandomAccessFile(randomAccessData.getAnotherInSameParent(name))
    }

    @Throws(IOException::class)
    override fun newSameInstance(): BufferedRandomAccess {
        return BufferedRandomAccessFile(randomAccessData.newSameInstance())
    }

    @Throws(IOException::class)
    override fun newFragment(offset: Long, length: Long): BufferedRandomAccess {
        return BufferedRandomAccessFile(randomAccessData.newFragment(offset, length))
    }

    @Throws(IOException::class)
    override fun flush() {
        flushBuffer()
    }

    @Throws(IOException::class)
    override fun close() {
        flush()
        closed = true
        randomAccessData.close()
    }

    override val isClosed: Boolean
        get() = closed

    @Throws(IOException::class)
    private fun flushBuffer() {
        if (dirty) {
            if (diskPos != lo) {
                randomAccessData.seek(lo)
            }
            val len = (curr - lo).toInt()
            randomAccessData.write(buff, 0, len)
            diskPos = curr
            dirty = false
            if (randomAccessDataLength != -1L && diskPos > randomAccessDataLength) {
                randomAccessDataLength = -1
            }
        }
    }

    @Throws(IOException::class)
    private fun fillBuffer(): Int {
        var cnt = 0
        var rem = buff.size
        while (rem > 0) {
            val n = randomAccessData.read(buff, cnt, rem)
            if (n < 0) break
            cnt += n
            rem -= n
        }
        hitEOF = cnt < buff.size
        if (hitEOF) {
            Arrays.fill(buff, cnt, buff.size, 0xff.toByte())
        }
        diskPos += cnt.toLong()
        return cnt
    }

    @Throws(IOException::class)
    private fun writeAtMost(b: ByteArray, off: Int, len: Int): Int {
        var targetLen = len
        if (curr >= hi) {
            if (hitEOF && hi < maxHi) {
                hi = maxHi
            } else {
                seek(curr)
                if (curr == hi) {
                    hi = maxHi
                }
            }
        }
        targetLen = min(targetLen, (hi - curr).toInt())
        val buffOff = (curr - lo).toInt()
        System.arraycopy(b, off, buff, buffOff, targetLen)
        curr += targetLen
        return targetLen
    }
}

