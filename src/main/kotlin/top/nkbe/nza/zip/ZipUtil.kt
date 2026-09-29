package top.nkbe.nza.zip

import java.io.EOFException
import java.io.IOException
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId

object ZipUtil {

    @JvmStatic
    fun dosToJavaTime(dosTime: Long): Long {
        val year = ((dosTime shr 25) and 0x7f).toInt() + 1980
        val month = ((dosTime shr 21) and 0x0f).toInt().coerceIn(1, 12)
        val day = ((dosTime shr 16) and 0x1f)
        val hour = ((dosTime shr 11) and 0x1f)
        val minute = ((dosTime shr 5) and 0x3f)
        val second = ((dosTime shl 1) and 0x3e)
        return LocalDateTime.of(year, month, 1, 0, 0)
            .plusDays(day - 1)
            .plusHours(hour)
            .plusMinutes(minute)
            .plusSeconds(second)
            .atZone(ZoneId.systemDefault())
            .toInstant()
            .toEpochMilli()
    }

    @JvmStatic
    fun javaToDosTime(time: Long): Long {
        val t = LocalDateTime.ofInstant(Instant.ofEpochMilli(time), ZoneId.systemDefault())
        if (t.year < 1980) {
            return (1L shl 21) or (1L shl 16)
        }
        return ((minOf(t.year - 1980, 127)).toLong() shl 25) or
                (t.monthValue.toLong() shl 21) or
                (t.dayOfMonth.toLong() shl 16) or
                (t.hour.toLong() shl 11) or
                (t.minute.toLong() shl 5) or
                (t.second.toLong() shr 1)
    }

    @JvmStatic
    @Throws(IOException::class)
    fun writeShort(array: ByteArray, pos: Int, value: Int) {
        if (pos + 2 > array.size) throw EOFException()
        array[pos] = value.toByte()
        array[pos + 1] = (value ushr 8).toByte()
    }

    @JvmStatic
    @Throws(IOException::class)
    fun writeLong(array: ByteArray, pos: Int, value: Long) {
        if (pos + 8 > array.size) throw EOFException()
        for (i in 0 until 8) {
            array[pos + i] = (value ushr (8 * i)).toByte()
        }
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
        var result = 0L
        for (i in 0 until 8) {
            result = result or ((b[off + i].toLong() and 0xFFL) shl (8 * i))
        }
        return result
    }
}
