package top.nkbe.nza.sign

import top.nkbe.nza.data.buffer.BufferedRandomAccess
import top.nkbe.nza.zip.EocdLocator
import java.io.IOException

class ZipBuffer(val file: BufferedRandomAccess) {
    companion object {
        const val APK_SIG_BLOCK_MAGIC_HI: Long = 0x3234206b636f6c42L
        const val APK_SIG_BLOCK_MAGIC_LO: Long = 0x20676953204b5041L
        const val APK_SIG_BLOCK_MIN_SIZE: Int = 32
    }

    val entriesDataSizeBytes: Long
    val centralDirectoryOffset: Long
    val centralDirectorySizeBytes: Long
    val eocdOffset: Long
    val hasApkSigBlock: Boolean

    init {
        val off = EocdLocator.find(file)
        if (off < 0) throw IOException("Archive is not a ZIP archive")

        eocdOffset = off
        file.seek(off + 12)
        centralDirectorySizeBytes = file.readUInt()
        centralDirectoryOffset = file.readUInt()

        var entriesDataEnd = centralDirectoryOffset
        var matchV2SigBlock = false
        try {
            if (centralDirectoryOffset >= APK_SIG_BLOCK_MIN_SIZE) {
                file.seek(centralDirectoryOffset - 16)
                if (file.readLong() == APK_SIG_BLOCK_MAGIC_LO && file.readLong() == APK_SIG_BLOCK_MAGIC_HI) {
                    file.seek(centralDirectoryOffset - 24)
                    val size = file.readLong()
                    val sigStart = centralDirectoryOffset - size - 8
                    file.seek(sigStart)
                    if (file.readLong() == size) {
                        matchV2SigBlock = true
                        entriesDataEnd = sigStart
                    }
                }
            }
        } catch (_: IOException) {
        }
        entriesDataSizeBytes = entriesDataEnd
        hasApkSigBlock = matchV2SigBlock
    }

    @Throws(IOException::class)
    fun length(): Long = file.length()
}
