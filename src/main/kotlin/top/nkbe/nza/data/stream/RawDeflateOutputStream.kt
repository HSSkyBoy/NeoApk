package top.nkbe.nza.data.stream

import java.io.IOException
import java.io.OutputStream
import java.util.zip.Deflater
import java.util.zip.DeflaterOutputStream

class RawDeflateOutputStream(
    outputStream: OutputStream,
    level: Int
) : DeflaterOutputStream(outputStream, Deflater(level, true)) {

    @Throws(IOException::class)
    override fun close() {
        super.close()
        def.end()
    }
}

