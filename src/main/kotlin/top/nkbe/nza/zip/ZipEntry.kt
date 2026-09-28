package top.nkbe.nza.zip

import java.io.IOException

class ZipEntry {
    companion object {
        const val UNKNOWN_SIZE: Long = -1L
    }

    var platform: Int = ZipConstant.PLATFORM_FAT
    var generalPurposeFlag: Int = 0
    var method: Int = 0
    var time: Long = 0
    var crc: Int = 0
    var compressedSize: Long = UNKNOWN_SIZE
    var size: Long = UNKNOWN_SIZE
    var internalAttributes: Int = 0
    var externalAttributes: Int = 0
    var headerOffset: Long = 0
    var dataOffset: Long = 0
    var extra: ByteArray? = null
    var commentData: ByteArray? = null

    private var _name: String = ""

    var name: String
        get() = _name
        set(value) {
            var n = value
            if (platform == ZipConstant.PLATFORM_FAT && !n.contains("/")) {
                n = n.replace('\\', '/')
            }
            _name = n
        }

    constructor()

    constructor(name: String) {
        this.name = name
    }

    val isDirectory: Boolean
        get() = name.endsWith("/")

    @Throws(IOException::class)
    fun setupZip64WithCenterDirectoryExtra(extra: ByteArray): Boolean {
        val record = ExtraDataRecord.find(extra, ZipConstant.ZIP64_EXTENDED_INFO_HEADER_ID.toInt())
        if (record == null) {
            if (compressedSize == ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE ||
                size == ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE ||
                headerOffset == ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE
            ) {
                throw IOException(
                    "File contains no zip64 extended info: name=$name, compressedSize=$compressedSize, size=$size, headerOffset=$headerOffset"
                )
            }
            return false
        }
        var offset = 0
        if (size == ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) {
            size = record.readLong(offset)
            offset += 8
        }
        if (compressedSize == ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) {
            compressedSize = record.readLong(offset)
            offset += 8
        }
        if (headerOffset == ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) {
            headerOffset = record.readLong(offset)
        }
        return true
    }

    fun setNameData(nameData: ByteArray) {
        this.name = String(nameData, ZipConstant.UTF_8)
    }
}

