package top.nkbe.nza.sign

internal object ByteArrayUtil {
    @JvmStatic
    fun setInt(value: Int, data: ByteArray, offset: Int) {
        data[offset] = (value and 0xff).toByte()
        data[offset + 1] = ((value ushr 8) and 0xff).toByte()
        data[offset + 2] = ((value ushr 16) and 0xff).toByte()
        data[offset + 3] = ((value ushr 24) and 0xff).toByte()
    }

    @JvmStatic
    fun setUInt(value: Long, data: ByteArray, offset: Int) {
        data[offset] = (value and 0xff).toByte()
        data[offset + 1] = ((value ushr 8) and 0xff).toByte()
        data[offset + 2] = ((value ushr 16) and 0xff).toByte()
        data[offset + 3] = ((value ushr 24) and 0xff).toByte()
    }

    @JvmStatic
    fun setLong(value: Long, data: ByteArray, offset: Int) {
        data[offset] = (value and 0xff).toByte()
        data[offset + 1] = ((value ushr 8) and 0xff).toByte()
        data[offset + 2] = ((value ushr 16) and 0xff).toByte()
        data[offset + 3] = ((value ushr 24) and 0xff).toByte()
        data[offset + 4] = ((value ushr 32) and 0xff).toByte()
        data[offset + 5] = ((value ushr 40) and 0xff).toByte()
        data[offset + 6] = ((value ushr 48) and 0xff).toByte()
        data[offset + 7] = ((value ushr 56) and 0xff).toByte()
    }

    @JvmStatic
    fun readUInt(data: ByteArray, offset: Int): Long {
        val ch1 = data[offset].toLong() and 0xffL
        val ch2 = data[offset + 1].toLong() and 0xffL
        val ch3 = data[offset + 2].toLong() and 0xffL
        val ch4 = data[offset + 3].toLong() and 0xffL
        return ch1 or (ch2 shl 8) or (ch3 shl 16) or (ch4 shl 24)
    }

    @JvmStatic
    fun intToBytes(value: Int): ByteArray {
        val array = ByteArray(4)
        setInt(value, array, 0)
        return array
    }
}

