package top.nkbe.nza.zip

import java.io.IOException
import java.util.Arrays
import java.util.HashSet

class ExtraDataRecord {

    companion object {
        private val KNOWN_HEADER: Set<Int> = HashSet(
            listOf(
                0x0001, 0x0007, 0x0008, 0x0009, 0x000a, 0x000c, 0x000d, 0x000e, 0x000f,
                0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x0020, 0x0021, 0x0022,
                0x0023, 0x0065, 0x0066, 0x4690, 0x07c8, 0x2605, 0x2705, 0x2805, 0x334d,
                0x4341, 0x4453, 0x4704, 0x470f, 0x4b46, 0x4c41, 0x4d49, 0x4f4c, 0x5356,
                0x5455, 0x554e, 0x5855, 0x6375, 0x6542, 0x7075, 0x756e, 0x7855, 0xa11e,
                0xa220, 0xfd4a, 0x9901, 0x9902
            )
        )

        /**
         * Trim invalid data from extra fields
         */
        @JvmStatic
        @Throws(IOException::class)
        fun trim(extra: ByteArray): ByteArray {
            var offset = 0
            while (extra.size - offset >= 4) {
                val header = ZipUtil.readUShort(extra, offset)
                val size = ZipUtil.readUShort(extra, offset + 2)
                if (!KNOWN_HEADER.contains(header) || offset + 4 + size > extra.size) {
                    break
                }
                offset += 4 + size
            }
            return Arrays.copyOf(extra, offset)
        }

        @JvmStatic
        @Throws(IOException::class)
        fun set(extra: ByteArray, header: Int, data: ByteArray): ByteArray {
            val stripped = remove(extra, header)
            val newExtra = ByteArray(4 + data.size + stripped.size)
            ZipUtil.writeShort(newExtra, 0, header)
            ZipUtil.writeShort(newExtra, 2, data.size)
            System.arraycopy(data, 0, newExtra, 4, data.size)
            System.arraycopy(stripped, 0, newExtra, 4 + data.size, stripped.size)
            return newExtra
        }

        @JvmStatic
        @Throws(IOException::class)
        fun remove(extra: ByteArray, header: Int): ByteArray {
            var offset = 0
            while (extra.size - offset >= 4) {
                val h = ZipUtil.readUShort(extra, offset)
                var size = ZipUtil.readUShort(extra, offset + 2)
                offset += 4
                if (size > extra.size - offset) return extra
                if (h != header) {
                    offset += size
                } else {
                    offset -= 4
                    size += 4
                    val bytes = ByteArray(extra.size - size)
                    System.arraycopy(extra, 0, bytes, 0, offset)
                    System.arraycopy(extra, offset + size, bytes, offset, extra.size - size - offset)
                    return bytes
                }
            }
            return extra
        }

        @JvmStatic
        @Throws(IOException::class)
        fun find(extra: ByteArray?, header: Int): ExtraDataRecord? {
            if (extra == null) return null
            var offset = 0
            while (extra.size - offset >= 4) {
                val h = ZipUtil.readUShort(extra, offset)
                val size = ZipUtil.readUShort(extra, offset + 2)
                offset += 4
                if (size > extra.size - offset) return null
                if (h != header) {
                    offset += size
                } else {
                    val bytes = ByteArray(size)
                    System.arraycopy(extra, offset, bytes, 0, size)
                    val record = ExtraDataRecord()
                    record.header = header
                    record.sizeOfData = size
                    record.data = bytes
                    return record
                }
            }
            return null
        }

        @JvmStatic
        @Throws(IOException::class)
        fun generateAESExtra(aesKeyStrength: Int, method: Int): ByteArray {
            val versionNumber = 2
            val vendorID = "AE"
            val data = ByteArray(7)
            ZipUtil.writeShort(data, 0, versionNumber)
            ZipUtil.writeBytes(data, 2, vendorID.toByteArray(ZipConstant.UTF_8))
            ZipUtil.writeByte(data, 4, aesKeyStrength)
            ZipUtil.writeShort(data, 5, method)
            return data
        }
    }

    var header: Int = 0
    var sizeOfData: Int = 0
    var data: ByteArray = ByteArray(0)

    @Throws(IOException::class)
    fun readUByte(off: Int): Int = ZipUtil.readUByte(data, off)

    @Throws(IOException::class)
    fun readUShort(off: Int): Int = ZipUtil.readUShort(data, off)

    @Throws(IOException::class)
    fun readInt(off: Int): Int = ZipUtil.readInt(data, off)

    @Throws(IOException::class)
    fun readLong(off: Int): Long = ZipUtil.readLong(data, off)
}

