package top.nkbe.nza.zip

import java.nio.charset.Charset
import java.nio.charset.StandardCharsets

object ZipConstant {
    @JvmField
    val UTF_8: Charset = StandardCharsets.UTF_8

    const val METHOD_STORED = 0
    const val METHOD_DEFLATED = 8

    const val PLATFORM_FAT = 0

    const val UTF8_NAMES_FLAG = 1 shl 11

    const val EXTRA_HEADER_UNICODE_NAME = 0x7075
    const val EXTRA_HEADER_UNICODE_COMMENT = 0x6375

    /** local file header signature */
    const val LFH_SIG = 0x04034B50

    /** local file data descriptor signature */
    const val EXT_SIG = 0x08074b50

    /** End of central dir signature */
    const val EOCD_SIG = 0x06054B50

    /** Central file header signature */
    const val CFH_SIG = 0x02014B50

    const val BUFF_SIZE = 1024 * 4

    const val SHORT = 2
    const val WORD = 4

    const val MIN_EOCD_SIZE = WORD + SHORT + SHORT + SHORT + SHORT + WORD + WORD + SHORT
    const val MAX_EOCD_SIZE = MIN_EOCD_SIZE + 0xFFFF

    const val CFD_LOCATOR_OFFSET = WORD + SHORT + SHORT + SHORT + SHORT + WORD

    const val LFH_OFFSET_FOR_FILENAME_LENGTH = WORD + SHORT + SHORT + SHORT + SHORT + SHORT + WORD + WORD + WORD

    /** The maximum supported entry / archive size for standard (non-zip64) entries and archives. */
    const val MAX_ZIP_ENTRY_AND_ARCHIVE_SIZE = 0x00000000ffffffffL

    const val ZIP64_LOCATOR_SIZE = 20
    const val ZIP64_LOCATOR_SIGNATURE = 0x07064b50
    const val ZIP64_EOCD_RECORD_SIGNATURE = 0x06064b50
    const val ZIP64_EXTENDED_INFO_HEADER_ID: Short = 0x0001
    const val ZIP64_EOCD_RECORD_EFFECTIVE_SIZE = 40
}

