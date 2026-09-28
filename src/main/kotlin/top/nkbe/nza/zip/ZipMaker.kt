package top.nkbe.nza.zip

import top.nkbe.nza.data.buffer.BufferedRandomAccess
import top.nkbe.nza.data.buffer.RandomAccessFactory
import top.nkbe.nza.data.stream.BridgeInputStream
import top.nkbe.nza.data.stream.BridgeOutputStream
import top.nkbe.nza.data.stream.CrcOutputStream
import top.nkbe.nza.data.stream.RawDeflateOutputStream
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.Charset
import java.util.Arrays
import java.util.Collections
import java.util.Objects
import java.util.zip.Deflater

class ZipMaker : Closeable {

    companion object {
        const val LEVEL_FASTEST = Deflater.BEST_SPEED
        const val LEVEL_FASTER = 3
        const val LEVEL_DEFAULT = Deflater.DEFAULT_COMPRESSION
        const val LEVEL_BETTER = 7
        const val LEVEL_BEST = Deflater.BEST_COMPRESSION

        const val METHOD_DEFLATED = ZipConstant.METHOD_DEFLATED
        const val METHOD_STORED = ZipConstant.METHOD_STORED

        @JvmStatic
        fun defaultAlignment(name: String, isHost: Boolean): Int {
            if (isHost
                || name.endsWith("origin.apk")
                || name.endsWith("origin_apk.bin")
                || name == "assets/npatch/origin.apk"
                || name == "assets/lspatch/origin.apk"
                || name == "assets/origin.apk"
            ) return 16384
            if (name.endsWith(".so")) {
                return if (name.contains("arm64-v8a") || name.contains("x86_64")) 16384 else 4096
            }
            if (name == "resources.arsc") return 4
            return 4
        }
    }

    val archive: BufferedRandomAccess

    private val headers = ArrayList<CenterFileHeader>()
    private var currentHeader: CenterFileHeader? = null

    var method: Int = METHOD_DEFLATED
    var level: Int = LEVEL_DEFAULT
    var encoding: Charset = ZipConstant.UTF_8
    var comment: String? = null
    var isForceZip64: Boolean = false
    private var needsZip64EocdRecord: Boolean = false

    var alignmentRule: (name: String, isHost: Boolean) -> Int = ::defaultAlignment

    private var topOutput: CrcOutputStream? = null
    private var bottomOutput: BridgeOutputStream? = null

    private val copyEntryBuffer = ByteArray(8 * 1024)

    @Throws(IOException::class)
    constructor(path: String) : this(File(path))

    @Throws(IOException::class)
    constructor(file: File) {
        if (file.exists()) {
            file.delete()
        }
        this.archive = RandomAccessFactory.from(file, "rw")
    }

    constructor(archive: BufferedRandomAccess) {
        this.archive = archive
    }

    @Throws(IOException::class)
    fun putNextEntry(name: String) {
        putNextEntry(CenterFileHeader(name))
    }

    @Throws(IOException::class)
    fun putNextEntry(ze: ZipEntry) {
        putNextEntry(CenterFileHeader(ze))
    }

    @Throws(IOException::class)
    private fun putNextEntry(header: CenterFileHeader) {
        if (currentHeader != null) {
            closeEntry()
        }
        header.headerOffset = archive.filePointer
        headers.add(header)

        if (!header.isDirectory) {
            currentHeader = header

            var generalPurposeFlag = 0
            val entryMethod = this.method

            val bOut = BridgeOutputStream(archive)
            bottomOutput = bOut
            var os: OutputStream = bOut

            if (header.isUtf8) {
                generalPurposeFlag = generalPurposeFlag or ZipConstant.UTF8_NAMES_FLAG
            }

            when (entryMethod) {
                METHOD_DEFLATED -> os = RawDeflateOutputStream(os, level)
                METHOD_STORED -> {}
                else -> throw IOException("Unsupported compression method $entryMethod")
            }

            topOutput = CrcOutputStream(os)
            header.generalPurposeFlag = generalPurposeFlag
            header.method = entryMethod
        } else {
            header.method = METHOD_STORED
            if (header.isUtf8) {
                header.generalPurposeFlag = ZipConstant.UTF8_NAMES_FLAG
            }
        }

        writeHeader(header)
        header.dataOffset = archive.filePointer
    }

    @Throws(IOException::class)
    fun putNextRawEntry(ze: ZipEntry) {
        if (currentHeader != null) {
            closeEntry()
        }
        val header = CenterFileHeader(ze)
        if (header.isUtf8) {
            header.generalPurposeFlag = header.generalPurposeFlag or ZipConstant.UTF8_NAMES_FLAG
        }
        header.headerOffset = archive.filePointer
        headers.add(header)
        writeHeader(header)
        header.dataOffset = archive.filePointer
    }

    @Throws(IOException::class)
    fun writeRaw(data: ByteArray) {
        writeRaw(data, 0, data.size)
    }

    @Throws(IOException::class)
    fun writeRaw(data: ByteArray, off: Int, len: Int) {
        archive.write(data, off, len)
    }

    @Throws(IOException::class)
    fun copyZipEntry(ze: ZipEntry, zipFile: ZipFile) {
        putNextRawEntry(ze)
        if (!ze.isDirectory) {
            zipFile.getRawInputStream(ze).use { `is` ->
                var len: Int
                while (`is`.read(copyEntryBuffer).also { len = it } != -1) {
                    writeRaw(copyEntryBuffer, 0, len)
                }
            }
        }
    }

    @Throws(IOException::class)
    fun putNextHostEntry(name: String, zipFile: ZipFile): HostEntryHolder {
        if (name.endsWith("/") || name.endsWith("\\")) {
            throw IOException("Invalid host entry name: $name")
        }
        val savedMethod = method
        method = METHOD_STORED
        val centerFileHeader = CenterFileHeader(name)
        centerFileHeader.isHost = true
        putNextEntry(centerFileHeader)
        method = savedMethod
        return HostEntryHolder(zipFile)
    }

    inner class HostEntryHolder internal constructor(private val zipFile: ZipFile) {
        private val hostHeader: CenterFileHeader = checkNotNull(currentHeader) { "Current header cannot be null" }

        init {
            zipFile.archive.newSameInstance().use { innerArchive ->
                writeFully(BridgeInputStream(innerArchive, 0, innerArchive.length()))
                closeEntry()
            }
        }

        val hostEntryHeaderOffset: Long
            get() = hostHeader.headerOffset

        @Throws(IOException::class)
        fun putNextVirtualEntry(name: String): Long {
            val innerEntry = zipFile.getEntryNonNull(name)
            val header = CenterFileHeader(innerEntry)
            setupNeedZip64(header)
            header.generalPurposeFlag = innerEntry.generalPurposeFlag
            header.headerOffset = innerEntry.headerOffset + hostHeader.dataOffset
            header.dataOffset = innerEntry.dataOffset + hostHeader.dataOffset
            headers.add(header)
            return header.headerOffset - hostHeader.headerOffset
        }
    }

    @Throws(IOException::class)
    private fun writeHeader(header: CenterFileHeader) {
        setupNeedZip64(header)

        archive.writeInt(ZipConstant.LFH_SIG)
        archive.writeUShort(header.version())
        archive.writeUShort(header.generalPurposeFlag)
        archive.writeUShort(header.method)
        archive.writeInt(header.time)
        archive.writeInt(header.crc)

        if (header.sizeNeedZip64) {
            archive.writeUInt(ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE)
            archive.writeUInt(ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE)
        } else {
            archive.writeUInt(header.compressedSize)
            archive.writeUInt(header.size)
        }
        archive.writeUShort(header.name.size)

        var extra: ByteArray
        if (header.sizeNeedZip64) {
            val data = ByteArray(2 * 8)
            ZipUtil.writeLong(data, 0, header.size)
            ZipUtil.writeLong(data, 8, header.compressedSize)
            extra = ExtraDataRecord.set(header.extra, ZipConstant.ZIP64_EXTENDED_INFO_HEADER_ID.toInt(), data)
        } else {
            extra = ExtraDataRecord.remove(header.extra, ZipConstant.ZIP64_EXTENDED_INFO_HEADER_ID.toInt())
        }

        // ZipAlign
        if (header.method == METHOD_STORED) {
            val entryName = String(header.name, ZipConstant.UTF_8)
            val alignment = alignmentRule(entryName, header.isHost)
            val extraDataOffset = archive.filePointer + 2 + header.name.size
            extra = align(alignment, extra, extraDataOffset)
        }

        archive.writeUShort(extra.size)
        archive.write(header.name)
        archive.write(extra)
    }

    private fun setupNeedZip64(header: CenterFileHeader) {
        if (isForceZip64) {
            header.sizeNeedZip64 = true
            header.offsetNeedZip64 = true
        } else {
            if (header.size >= 0xf0000000L && header.compressedSize == ZipEntry.UNKNOWN_SIZE) {
                header.sizeNeedZip64 = true
            } else if (header.size >= ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE ||
                header.compressedSize >= ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE
            ) {
                header.sizeNeedZip64 = true
            }
            if (header.headerOffset >= ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE) {
                header.offsetNeedZip64 = true
            }
        }
        if (header.needZip64()) {
            needsZip64EocdRecord = true
        }
        if (header.size == ZipEntry.UNKNOWN_SIZE) {
            header.size = 0
        }
        if (header.compressedSize == ZipEntry.UNKNOWN_SIZE) {
            header.compressedSize = 0
        }
    }

    @Throws(IOException::class)
    fun write(b: Int) {
        topOutput?.write(b) ?: throw IOException("No current entry")
    }

    @Throws(IOException::class)
    fun write(data: ByteArray) {
        topOutput?.write(data) ?: throw IOException("No current entry")
    }

    @Throws(IOException::class)
    fun write(data: ByteArray, off: Int, len: Int) {
        topOutput?.write(data, off, len) ?: throw IOException("No current entry")
    }

    @Throws(IOException::class)
    fun writeFully(`is`: InputStream) {
        val b = ByteArray(copyEntryBuffer.size)
        var len: Int
        while (`is`.read(b).also { len = it } > 0) {
            write(b, 0, len)
        }
    }

    @Throws(IOException::class)
    fun closeEntry() {
        val cur = currentHeader ?: return
        val top = topOutput ?: return
        val bottom = bottomOutput ?: return

        top.close()

        cur.crc = top.crc
        cur.compressedSize = bottom.count
        cur.size = top.count

        val saved = archive.filePointer
        archive.seek(cur.headerOffset + ZipConstant.WORD + ZipConstant.SHORT + ZipConstant.SHORT + ZipConstant.SHORT + ZipConstant.WORD)
        archive.writeInt(cur.crc)

        if (cur.sizeNeedZip64) {
            archive.writeUInt(ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE)
            archive.writeUInt(ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE)

            // skip nameLength + extraLength + nameData
            archive.skipBytes(ZipConstant.SHORT + ZipConstant.SHORT + cur.name.size)

            // skip zip64Extra (header + size)
            archive.skipBytes(4)

            // update local extra
            archive.writeLong(cur.size)
            archive.writeLong(cur.compressedSize)
        } else {
            if (cur.compressedSize >= ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE ||
                cur.size >= ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE
            ) {
                throw IOException(
                    "Zip entry size needs zip64: name=${String(cur.name)}, compressedSize=${cur.compressedSize}, size=${cur.size}"
                )
            }
            archive.writeUInt(cur.compressedSize)
            archive.writeUInt(cur.size)
        }

        archive.seek(saved)

        topOutput = null
        bottomOutput = null
        currentHeader = null
    }

    @Throws(IOException::class)
    override fun close() {
        if (archive.isClosed) return
        if (currentHeader != null) {
            closeEntry()
        }
        val cdOffset = archive.filePointer
        Collections.sort(headers)

        for (header in headers) {
            writeCentralFileHeader(header)
        }

        val cdSize = archive.filePointer - cdOffset
        writeCentralDirectoryEnd(cdSize, cdOffset)
        archive.close()
    }

    @Throws(IOException::class)
    private fun align(alignment: Int, extra: ByteArray, extraDataOffset: Long): ByteArray {
        if (alignment <= 1) return extra
        if (isAligned(extraDataOffset + extra.size, alignment)) {
            return extra
        }
        val trimmed = ExtraDataRecord.trim(extra)
        val padding = getAlignedPadding(extraDataOffset + trimmed.size, alignment)
        return Arrays.copyOf(trimmed, trimmed.size + padding)
    }

    private fun isAligned(pos: Long, alignTo: Int): Boolean = (pos % alignTo) == 0L

    private fun getAlignedPadding(pos: Long, alignTo: Int): Int =
        ((alignTo - (pos % alignTo)) % alignTo).toInt()

    @Throws(IOException::class)
    private fun writeCentralFileHeader(header: CenterFileHeader) {
        val needZip64 = header.needZip64()
        var extra: ByteArray
        if (needZip64) {
            val data = ByteArray(3 * 8)
            ZipUtil.writeLong(data, 0, header.size)
            ZipUtil.writeLong(data, 8, header.compressedSize)
            ZipUtil.writeLong(data, 16, header.headerOffset)
            extra = ExtraDataRecord.set(header.extra, ZipConstant.ZIP64_EXTENDED_INFO_HEADER_ID.toInt(), data)
        } else {
            extra = ExtraDataRecord.remove(header.extra, ZipConstant.ZIP64_EXTENDED_INFO_HEADER_ID.toInt())
        }

        archive.writeInt(ZipConstant.CFH_SIG)
        archive.writeUShort(maxOf(20, header.version()))
        archive.writeUShort(header.version())
        archive.writeUShort(header.generalPurposeFlag)
        archive.writeUShort(header.method)
        archive.writeInt(header.time)
        archive.writeInt(header.crc)

        if (needZip64) {
            archive.writeUInt(ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE)
            archive.writeUInt(ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE)
        } else {
            archive.writeUInt(header.compressedSize)
            archive.writeUInt(header.size)
        }

        archive.writeUShort(header.name.size)
        archive.writeUShort(extra.size)
        archive.writeUShort(header.comment.size)
        archive.writeUShort(header.diskNumberStart)
        archive.writeUShort(header.internalAttributes)
        archive.writeInt(header.externalAttributes)

        if (needZip64) {
            archive.writeUInt(ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE)
        } else {
            archive.writeUInt(header.headerOffset)
        }

        archive.write(header.name)
        archive.write(extra)
        archive.write(header.comment)
    }

    @Throws(IOException::class)
    private fun writeCentralDirectoryEnd(cdSize: Long, cdOffset: Long) {
        if (headers.size >= 0xffff) {
            needsZip64EocdRecord = true
        }
        if (needsZip64EocdRecord) {
            // Zip64 end of central directory record
            archive.writeInt(ZipConstant.ZIP64_EOCD_RECORD_SIGNATURE)
            archive.writeLong((ZipConstant.ZIP64_EOCD_RECORD_EFFECTIVE_SIZE + 4).toLong())
            archive.writeUShort(20)
            archive.writeUShort(20)
            archive.writeInt(0) // disk number
            archive.writeInt(0) // disk with central dir
            archive.writeLong(headers.size.toLong())
            archive.writeLong(headers.size.toLong())
            archive.writeLong(cdSize)
            archive.writeLong(cdOffset)

            // Zip64 end of central directory locator
            archive.writeInt(ZipConstant.ZIP64_LOCATOR_SIGNATURE)
            archive.writeInt(0)
            archive.writeLong(cdSize + cdOffset)
            archive.writeInt(1)
        }

        val commentBytes = comment?.toByteArray(encoding) ?: ByteArray(0)
        archive.writeInt(ZipConstant.EOCD_SIG)
        archive.writeUShort(0)
        archive.writeUShort(0)

        if (needsZip64EocdRecord) {
            archive.writeUShort(0xFFFF)
            archive.writeUShort(0xFFFF)
            archive.writeUInt(ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE)
            archive.writeUInt(ZipConstant.MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE)
        } else {
            archive.writeUShort(headers.size)
            archive.writeUShort(headers.size)
            archive.writeUInt(cdSize)
            archive.writeUInt(cdOffset)
        }

        archive.writeUShort(commentBytes.size)
        archive.write(commentBytes)
    }

    private fun BufferedRandomAccess.writeUInt(v: Long) {
        if (v < 0 || v > 0xffffffffL) {
            throw IOException("Value out of unsigned int: $v")
        }
        writeInt(v.toInt())
    }
}

