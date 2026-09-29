package top.nkbe.nza.zip

import top.nkbe.nza.data.buffer.BufferedRandomAccess
import java.io.IOException

internal object EocdLocator {
    /** Returns the offset of the End Of Central Directory record, or -1 if none is found. */
    @Throws(IOException::class)
    fun find(file: BufferedRandomAccess): Long {
        val length = file.length()
        if (length < ZipConstant.MIN_EOCD_SIZE) return -1L
        val tailStart = maxOf(0L, length - ZipConstant.MAX_EOCD_SIZE)
        val tail = ByteArray((length - tailStart).toInt())
        file.seek(tailStart)
        file.readFully(tail)

        val sig = ZipConstant.EOCD_SIG
        val b0 = sig.toByte()
        val b1 = (sig ushr 8).toByte()
        val b2 = (sig ushr 16).toByte()
        val b3 = (sig ushr 24).toByte()
        for (i in tail.size - ZipConstant.MIN_EOCD_SIZE downTo 0) {
            if (tail[i] == b0 && tail[i + 1] == b1 && tail[i + 2] == b2 && tail[i + 3] == b3) {
                return tailStart + i
            }
        }
        return -1L
    }
}
