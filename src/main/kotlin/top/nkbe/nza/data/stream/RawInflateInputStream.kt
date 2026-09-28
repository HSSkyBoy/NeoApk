package top.nkbe.nza.data.stream

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream
import java.util.zip.ZipException

class RawInflateInputStream(
    val entryName: String,
    inputStream: InputStream
) : InflaterInputStream(inputStream, Inflater(true)) {

    @Throws(IOException::class)
    override fun read(b: ByteArray, off: Int, len: Int): Int {
        return try {
            super.read(b, off, len)
        } catch (e: ZipException) {
            throw ZipException("Decompression error: ${e.message} ($entryName)")
        } catch (e: EOFException) {
            -1
        }
    }

    override fun close() {
        super.close()
        inf.end()
    }
}

