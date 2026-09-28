package top.nkbe.nza.zip

class CenterFileHeader : Comparable<CenterFileHeader> {
    var generalPurposeFlag: Int = 0
    var method: Int = 0
    var time: Int = 0
    var crc: Int = 0
    var compressedSize: Long = ZipEntry.UNKNOWN_SIZE
    var size: Long = ZipEntry.UNKNOWN_SIZE
    var nameStr: String
    var name: ByteArray
    var extra: ByteArray = ByteArray(0)
    var comment: ByteArray = ByteArray(0)
    var diskNumberStart: Int = 0
    var internalAttributes: Int = 0
    var externalAttributes: Int = 0
    var headerOffset: Long = 0
    var dataOffset: Long = 0
    var isDirectory: Boolean = false
    var isUtf8: Boolean = true
    var isHost: Boolean = false
    var sizeNeedZip64: Boolean = false
    var offsetNeedZip64: Boolean = false

    constructor(name: String) {
        this.nameStr = name
        this.name = name.toByteArray(ZipConstant.UTF_8)
        this.isUtf8 = true
        this.time = ZipUtil.javaToDosTime(System.currentTimeMillis()).toInt()
        this.isDirectory = name.endsWith("/") || name.endsWith("\\")
        this.compressedSize = ZipEntry.UNKNOWN_SIZE
        this.size = ZipEntry.UNKNOWN_SIZE
    }

    constructor(entry: ZipEntry) {
        this.nameStr = entry.name
        this.name = entry.name.toByteArray(ZipConstant.UTF_8)
        this.isUtf8 = true
        this.time = ZipUtil.javaToDosTime(entry.time).toInt()
        this.method = entry.method
        this.crc = entry.crc
        this.compressedSize = entry.compressedSize
        this.size = entry.size
        this.extra = entry.extra ?: ByteArray(0)
        this.comment = entry.commentData ?: ByteArray(0)
        this.internalAttributes = entry.internalAttributes
        this.externalAttributes = entry.externalAttributes
        this.isDirectory = entry.isDirectory
    }

    fun needZip64(): Boolean = sizeNeedZip64 || offsetNeedZip64

    fun isEncrypted(): Boolean = (generalPurposeFlag and 1) != 0

    fun version(): Int {
        return when {
            needZip64() -> 45
            method == ZipConstant.METHOD_STORED && !isEncrypted() -> 10
            else -> 20
        }
    }

    override fun compareTo(other: CenterFileHeader): Int {
        return nameStr.compareTo(other.nameStr)
    }
}

