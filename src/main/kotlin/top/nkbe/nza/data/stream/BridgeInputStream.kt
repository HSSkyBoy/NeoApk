package top.nkbe.nza.data.stream

import top.nkbe.nza.data.buffer.BufferedRandomAccess
import java.io.IOException
import java.io.InputStream
import kotlin.math.min

class BridgeInputStream(
    private val archive: BufferedRandomAccess,
    start: Long,
    private var remaining: Long
) : InputStream() {

    private var loc: Long = start

    @Throws(IOException::class)
    override fun read(): Int {
        if (remaining-- <= 0) {
            return -1
        }
        synchronized(archive) {
            archive.seek(loc++)
            return archive.read()
        }
    }

    override fun available(): Int {
        return (remaining and Int.MAX_VALUE.toLong()).toInt()
    }

    @Throws(IOException::class)
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (remaining <= 0) {
            return -1
        }
        if (len <= 0) {
            return 0
        }
        val targetLen = min(len.toLong(), remaining).toInt()
        val ret: Int
        synchronized(archive) {
            archive.seek(loc)
            ret = archive.read(b, off, targetLen)
        }
        if (ret > 0) {
            loc += ret
            remaining -= ret
        }
        return ret
    }
}

