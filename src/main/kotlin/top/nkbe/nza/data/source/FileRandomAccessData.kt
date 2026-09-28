package top.nkbe.nza.data.source

import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.io.RandomAccessFile

class FileRandomAccessData(
    val file: File,
    val mode: String
) : RandomAccessData {

    @Throws(FileNotFoundException::class)
    constructor(path: String, mode: String) : this(File(path), mode)

    private val randomAccessFile: RandomAccessFile = RandomAccessFile(file, mode)

    @Throws(IOException::class)
    override fun seek(pos: Long) {
        randomAccessFile.seek(pos)
    }

    @Throws(IOException::class)
    override fun read(data: ByteArray, off: Int, len: Int): Int {
        return randomAccessFile.read(data, off, len)
    }

    @Throws(IOException::class)
    override fun write(data: ByteArray, off: Int, len: Int) {
        randomAccessFile.write(data, off, len)
    }

    @Throws(IOException::class)
    override fun length(): Long = randomAccessFile.length()

    @Throws(IOException::class)
    override fun setLength(newLength: Long) {
        randomAccessFile.setLength(newLength)
    }

    @Throws(IOException::class)
    override fun position(): Long = randomAccessFile.filePointer

    @Throws(IOException::class)
    override fun sync() {
        randomAccessFile.fd.sync()
    }

    override val name: String
        get() = file.name

    @Throws(IOException::class)
    override fun getAnotherInSameParent(name: String): RandomAccessData {
        val another = File(file.parentFile, name)
        return FileRandomAccessData(another, mode)
    }

    @Throws(IOException::class)
    override fun newSameInstance(): RandomAccessData {
        return FileRandomAccessData(file, mode)
    }

    @Throws(IOException::class)
    override fun close() {
        randomAccessFile.close()
    }
}

