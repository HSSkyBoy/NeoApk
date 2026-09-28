package top.nkbe.nza.data.stream

import top.nkbe.nza.data.buffer.BufferedRandomAccess
import java.io.IOException
import java.io.OutputStream

class BridgeOutputStream(
    private val archive: BufferedRandomAccess
) : OutputStream() {

    var count: Long = 0
        private set

    @Throws(IOException::class)
    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len > 0) {
            archive.write(b, off, len)
            count += len.toLong()
        }
    }

    @Throws(IOException::class)
    override fun write(b: Int) {
        archive.write(b)
        count++
    }
}

