package top.nkbe.nza.zip

import java.io.EOFException
import java.io.IOException
import java.util.Calendar

object ZipUtil {
    private val CALENDAR: Calendar = Calendar.getInstance()

    @JvmStatic
    fun dosToJavaTime(dosTime: Long): Long {
        synchronized(CALENDAR) {
            CALENDAR.set(Calendar.YEAR, ((dosTime shr 25) and 0x7f).toInt() + 1980)
            CALENDAR.set(Calendar.MONTH, ((dosTime shr 21) and 0x0f).toInt() - 1)
            CALENDAR.set(Calendar.DATE, ((dosTime shr 16) and 0x1f).toInt())
            CALENDAR.set(Calendar.HOUR_OF_DAY, ((dosTime shr 11) and 0x1f).toInt())
            CALENDAR.set(Calendar.MINUTE, ((dosTime shr 5) and 0x3f).toInt())
            CALENDAR.set(Calendar.SECOND, ((dosTime shl 1) and 0x3e).toInt())
            return CALENDAR.time.time
        }
    }

    @JvmStatic
    fun javaToDosTime(time: Long): Long {
        synchronized(CALENDAR) {
            CALENDAR.timeInMillis = time
            val year = CALENDAR.get(Calendar.YEAR)
            if (year < 1980) {
                return (1L shl 21) or (1L shl 16)
            }
            return ((year - 1980L) shl 25) or
                    ((CALENDAR.get(Calendar.MONTH) + 1L) shl 21) or
                    (CALENDAR.get(Calendar.DATE).toLong() shl 16) or
                    (CALENDAR.get(Calendar.HOUR_OF_DAY).toLong() shl 11) or
                    (CALENDAR.get(Calendar.MINUTE).toLong() shl 5) or
                    (CALENDAR.get(Calendar.SECOND).toLong() shr 1)
        }
    }

    @JvmStatic
    @Throws(IOException::class)
    fun writeByte(array: ByteArray, pos: Int, value: Int) {
        if (pos + 1 > array.size) throw EOFException()
        array[pos] = (value and 0xFF).toByte()
    }

    @JvmStatic
    @Throws(IOException::class)
    fun writeShort(array: ByteArray, pos: Int, value: Int) {
        if (pos + 2 > array.size) throw EOFException()
        array[pos] = (value and 0xFF).toByte()
        array[pos + 1] = ((value ushr 8) and 0xFF).toByte()
    }

    @JvmStatic
    @Throws(IOException::class)
    fun writeLong(array: ByteArray, pos: Int, value: Long) {
        if (pos + 8 > array.size) throw EOFException()
        array[pos] = (value and 0xFF).toByte()
        array[pos + 1] = ((value ushr 8) and 0xFF).toByte()
        array[pos + 2] = ((value ushr 16) and 0xFF).toByte()
        array[pos + 3] = ((value ushr 24) and 0xFF).toByte()
        array[pos + 4] = ((value ushr 32) and 0xFF).toByte()
        array[pos + 5] = ((value ushr 40) and 0xFF).toByte()
        array[pos + 6] = ((value ushr 48) and 0xFF).toByte()
        array[pos + 7] = ((value ushr 56) and 0xFF).toByte()
    }

    @JvmStatic
    @Throws(IOException::class)
    fun writeBytes(array: ByteArray, pos: Int, value: ByteArray) {
        if (pos + value.size > array.size) throw EOFException()
        System.arraycopy(value, 0, array, pos, value.size)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun readUByte(b: ByteArray, off: Int): Int {
        if (off + 1 > b.size) throw EOFException()
        return b[off].toInt() and 0xFF
    }

    @JvmStatic
    @Throws(IOException::class)
    fun readUShort(b: ByteArray, off: Int): Int {
        if (off + 2 > b.size) throw EOFException()
        return (b[off].toInt() and 0xFF) or ((b[off + 1].toInt() and 0xFF) shl 8)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun readInt(b: ByteArray, off: Int): Int {
        if (off + 4 > b.size) throw EOFException()
        return (b[off].toInt() and 0xFF) or
                ((b[off + 1].toInt() and 0xFF) shl 8) or
                ((b[off + 2].toInt() and 0xFF) shl 16) or
                ((b[off + 3].toInt() and 0xFF) shl 24)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun readLong(b: ByteArray, off: Int): Long {
        if (off + 8 > b.size) throw EOFException()
        return (b[off].toLong() and 0xFFL) or
                ((b[off + 1].toLong() and 0xFFL) shl 8) or
                ((b[off + 2].toLong() and 0xFFL) shl 16) or
                ((b[off + 3].toLong() and 0xFFL) shl 24) or
                ((b[off + 4].toLong() and 0xFFL) shl 32) or
                ((b[off + 5].toLong() and 0xFFL) shl 40) or
                ((b[off + 6].toLong() and 0xFFL) shl 48) or
                ((b[off + 7].toLong() and 0xFFL) shl 56)
    }
}

