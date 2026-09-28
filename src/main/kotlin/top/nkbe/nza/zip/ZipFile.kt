package top.nkbe.nza.zip

import top.nkbe.nza.data.buffer.BufferedRandomAccess
import top.nkbe.nza.data.buffer.RandomAccessFactory
import top.nkbe.nza.data.stream.BridgeInputStream
import top.nkbe.nza.data.stream.RawInflateInputStream
import java.io.BufferedInputStream
import java.io.Closeable
import java.io.EOFException
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.Collections
import java.util.LinkedHashMap

class ZipFile(
    val archive: BufferedRandomAccess
) : Closeable {

    private val entries = LinkedHashMap<String, ZipEntry>()
    private var closed = false

    @Throws(IOException::class)
    constructor(file: File) : this(RandomAccessFactory.from(file, "r"))

    init {
        readEntries()
    }

    fun getEntry(name: String): ZipEntry? = entries[name]

    @Throws(IOException::class)
    fun getEntryNonNull(name: String): ZipEntry {
        return entries[name] ?: throw IOException("Entry not found: $name")
    }

    fun getEntries(): List<ZipEntry> = ArrayList(entries.values)

    val entrySize: Int
        get() = entries.size

    @Throws(IOException::class)
    private fun readEntries() {
        val eocdRecord = readEocdRecord() ?: throw IOException("EOCD not found")
        val list = ArrayList<ZipEntry>()
        val zip64 = eocdRecord.zip64
        seek(eocdRecord.centralDirOffset)

        while (readInt() == ZipConstant.CFH_SIG) {
            val ze = ZipEntry()
            val versionMadeBy = readUShort()
            ze.platform = (versionMadeBy shr 8) and 0xF

            readUShort() // skip version info
            ze.generalPurposeFlag = readUShort()
            ze.method = readUShort()
            ze.time = ZipUtil.dosToJavaTime(readUInt())
            ze.crc = readInt()
            ze.compressedSize = readUInt()
            ze.size = readUInt()

            val fileNameLen = readUShort()
            val extraLen = readUShort()
            val commentLen = readUShort()

            readUShort() // disk number
            ze.internalAttributes = readUShort()
            ze.externalAttributes = readInt()
            ze.headerOffset = readUInt()
            ze.setNameData(readBytes(fileNameLen))

            if (extraLen > 0) {
                if (zip64) {
                    ze.setupZip64WithCenterDirectoryExtra(readBytes(extraLen))
                } else {
                    skip(extraLen.toLong())
                }
            }

            if (commentLen > 0) {
                try {
                    ze.commentData = readBytes(commentLen)
                } catch (_: IOException) {
                }
            }

            list.add(ze)
        }

        list.sortWith(Comparator { e1, e2 -> e1.headerOffset.compareTo(e2.headerOffset) })
        val ok = HashSet<String>(list.size)

        for (entry in list) {
            try {
                val offset = entry.headerOffset
                seek(offset + ZipConstant.LFH_OFFSET_FOR_FILENAME_LENGTH)
                val fileNameLen = readUShort()
                val extraLen = readUShort()
                skip(fileNameLen.toLong())
                var extra = readBytes(extraLen)
                extra = ExtraDataRecord.remove(extra, ZipConstant.ZIP64_EXTENDED_INFO_HEADER_ID.toInt())
                entry.extra = extra
                entry.dataOffset = offset + ZipConstant.LFH_OFFSET_FOR_FILENAME_LENGTH +
                        ZipConstant.SHORT + ZipConstant.SHORT + fileNameLen + extraLen
                ok.add(entry.name)
            } catch (e: EOFException) {
                // Log and ignore corrupt individual headers
            }
        }

        entries.clear()
        for (entry in list) {
            val key = entry.name
            if (ok.contains(key)) {
                entries[key] = entry
            }
        }
    }

    @Throws(IOException::class)
    private fun readEocdRecord(): EocdRecord? {
        val length = archive.length()
        var off = length - ZipConstant.MIN_EOCD_SIZE
        val stopSearching = maxOf(0L, length - ZipConstant.MAX_EOCD_SIZE)
        var found = false
        while (off >= stopSearching) {
            seek(off)
            if (readInt() == ZipConstant.EOCD_SIG) {
                found = true
                break
            }
            off--
        }
        if (!found) return null

        return try {
            val zip64EocdRecordOffset = parseZip64EocdRecordLocator(off)
            var record = parseEocdRecord(off + 4, zip64EocdRecordOffset != -1L)
            if (record.commentLength > 0) {
                try {
                    readBytes(record.commentLength)
                } catch (_: IOException) {
                    record = EocdRecord(record.numEntries, record.centralDirOffset, 0, record.zip64)
                }
            }
            if (zip64EocdRecordOffset != -1L) {
                record = parseZip64EocdRecord(zip64EocdRecordOffset, record.commentLength)
            }
            record
        } catch (e: IOException) {
            null
        }
    }

    @Throws(IOException::class)
    private fun parseZip64EocdRecordLocator(eocdOffset: Long): Long {
        if (eocdOffset > ZipConstant.ZIP64_LOCATOR_SIZE) {
            seek(eocdOffset - ZipConstant.ZIP64_LOCATOR_SIZE)
            if (readInt() == ZipConstant.ZIP64_LOCATOR_SIGNATURE) {
                val diskWithCentralDir = readInt()
                val zip64EocdRecordOffset = readLong()
                val numDisks = readInt()
                if (numDisks != 1 || diskWithCentralDir != 0) {
                    throw IOException("Spanned archives not supported")
                }
                return zip64EocdRecordOffset
            }
        }
        return -1L
    }

    @Throws(IOException::class)
    private fun parseEocdRecord(offset: Long, isZip64: Boolean): EocdRecord {
        seek(offset)
        val numEntries: Long
        val centralDirOffset: Long
        if (isZip64) {
            numEntries = -1
            centralDirOffset = -1
            skip(16)
        } else {
            skip(4)
            numEntries = readUShort().toLong()
            skip(6)
            centralDirOffset = readUInt()
        }
        val commentLength = readUShort()
        return EocdRecord(numEntries, centralDirOffset, commentLength, false)
    }

    @Throws(IOException::class)
    private fun parseZip64EocdRecord(eocdRecordOffset: Long, commentLength: Int): EocdRecord {
        seek(eocdRecordOffset)
        val signature = readInt()
        if (signature != ZipConstant.ZIP64_EOCD_RECORD_SIGNATURE) {
            throw IOException("Invalid zip64 eocd record offset, sig=${Integer.toHexString(signature)} offset=$eocdRecordOffset")
        }
        skip(12)
        val diskNumber = readInt()
        val diskWithCentralDirStart = readInt()
        val numEntries = readLong()
        val totalNumEntries = readLong()
        readLong()
        val centralDirOffset = readLong()
        if (numEntries != totalNumEntries || diskNumber != 0 || diskWithCentralDirStart != 0) {
            throw IOException("Spanned archives not supported: numEntries=$numEntries, totalNumEntries=$totalNumEntries, diskNumber=$diskNumber, diskWithCentralDirStart=$diskWithCentralDirStart")
        }
        return EocdRecord(numEntries, centralDirOffset, commentLength, true)
    }

    fun getRawInputStream(ze: ZipEntry): InputStream {
        return BridgeInputStream(archive, ze.dataOffset, ze.compressedSize)
    }

    @Throws(IOException::class)
    fun getInputStream(ze: ZipEntry): InputStream {
        val start = ze.dataOffset
        val method = ze.method
        var `is`: InputStream = BridgeInputStream(
            archive,
            start,
            if (method == ZipConstant.METHOD_STORED) ze.size else ze.compressedSize
        )
        when (method) {
            ZipConstant.METHOD_DEFLATED -> `is` = RawInflateInputStream(ze.name, `is`)
            ZipConstant.METHOD_STORED -> {}
            else -> throw IOException("Unsupported compression method ${ze.method} (${ze.name})")
        }
        if (method != ZipConstant.METHOD_STORED) {
            `is` = BufferedInputStream(`is`, 64 * 1024)
        }
        return `is`
    }

    @Throws(IOException::class)
    fun openEntryAsZipFile(entry: ZipEntry): ZipFile {
        if (entry.method != ZipConstant.METHOD_STORED) {
            throw IOException("Entry is not stored: ${entry.name}")
        }
        return ZipFile(archive.newFragment(entry.dataOffset, entry.compressedSize))
    }

    private fun seek(position: Long) {
        archive.seek(position)
    }

    @Throws(IOException::class)
    private fun skip(length: Long) {
        if (length < 0) throw IOException("Skip $length")
        val pos = archive.filePointer + length
        val len = archive.length()
        if (pos > len) throw EOFException()
        archive.seek(pos)
    }

    @Throws(IOException::class)
    private fun readBytes(len: Int): ByteArray {
        val bytes = ByteArray(len)
        archive.readFully(bytes)
        return bytes
    }

    @Throws(IOException::class)
    private fun readInt(): Int {
        val ch1 = archive.read()
        val ch2 = archive.read()
        val ch3 = archive.read()
        val ch4 = archive.read()
        if ((ch1 or ch2 or ch3 or ch4) < 0) throw EOFException()
        return ch1 or (ch2 shl 8) or (ch3 shl 16) or (ch4 shl 24)
    }

    @Throws(IOException::class)
    private fun readUShort(): Int {
        val ch1 = archive.read()
        val ch2 = archive.read()
        if ((ch1 or ch2) < 0) throw EOFException()
        return ch1 or (ch2 shl 8)
    }

    @Throws(IOException::class)
    private fun readUInt(): Long = readInt().toLong() and 0xFFFFFFFFL

    @Throws(IOException::class)
    private fun readLong(): Long = readUInt() or (readUInt() shl 32)

    @Throws(IOException::class)
    override fun close() {
        if (closed) return
        archive.close()
        closed = true
    }

    private data class EocdRecord(
        val numEntries: Long,
        val centralDirOffset: Long,
        val commentLength: Int,
        val zip64: Boolean
    )
}

