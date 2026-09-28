package top.nkbe.nza.data.buffer

import top.nkbe.nza.data.source.FileRandomAccessData
import top.nkbe.nza.data.source.RandomAccessData
import java.io.File
import java.io.IOException

object RandomAccessFactory {

    @JvmStatic
    fun from(randomAccessData: RandomAccessData): BufferedRandomAccess =
        BufferedRandomAccessFile(randomAccessData)

    @JvmStatic
    @Throws(IOException::class)
    fun from(file: File, mode: String = "r"): BufferedRandomAccess =
        BufferedRandomAccessFile(FileRandomAccessData(file, mode))

    @JvmStatic
    @Throws(IOException::class)
    fun from(path: String, mode: String = "r"): BufferedRandomAccess =
        BufferedRandomAccessFile(FileRandomAccessData(path, mode))
}

