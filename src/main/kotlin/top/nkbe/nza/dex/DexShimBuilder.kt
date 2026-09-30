package top.nkbe.nza.dex

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.Adler32

/**
 * Emits a minimal, self-contained DEX (format 035) that declares exactly one class:
 *
 *   public class <className> extends <superName> { public <init>() { super.<init>(); } }
 *
 * The class carries no fields and no methods beyond the default constructor, and overrides
 * nothing. Its only purpose is to be named by a patched manifest's `appComponentFactory` so the
 * platform instantiates it (running its superclass's static initializer) without the manifest ever
 * naming a foreign bootstrap class. Because it carries no host method bodies, it cannot reference
 * host classes that are absent from the class loader that loads it.
 *
 * Only this one shape is ever produced, so the whole layout is fixed except for the two variable
 * type descriptors -- this is a purpose-built emitter, not a general DEX writer.
 */
object DexShimBuilder {

    private val DEX_MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00) // "dex\n035\0"
    private const val ENDIAN_TAG = 0x12345678
    private const val HEADER_SIZE = 112
    private const val NO_INDEX = -1 // 0xffffffff
    private const val ACC_PUBLIC = 0x0001
    private const val ACC_CONSTRUCTOR = 0x10000

    // map_item type codes
    private const val TYPE_HEADER = 0x0000
    private const val TYPE_STRING_ID = 0x0001
    private const val TYPE_TYPE_ID = 0x0002
    private const val TYPE_PROTO_ID = 0x0003
    private const val TYPE_METHOD_ID = 0x0005
    private const val TYPE_CLASS_DEF = 0x0006
    private const val TYPE_MAP_LIST = 0x1000
    private const val TYPE_CLASS_DATA = 0x2000
    private const val TYPE_CODE = 0x2001
    private const val TYPE_STRING_DATA = 0x2002

    /**
     * @param className fully-qualified Java name of the class to declare (e.g. `com.host.RealFactory`)
     * @param superName fully-qualified Java name of its superclass (the NPatch bootstrap stub)
     */
    @JvmStatic
    fun buildFactoryShim(className: String, superName: String): ByteArray {
        require(className.isNotEmpty()) { "className is empty" }
        require(superName.isNotEmpty()) { "superName is empty" }

        val classDesc = toDescriptor(className)
        val superDesc = toDescriptor(superName)
        val initName = "<init>"
        val voidDesc = "V"
        require(classDesc != superDesc) { "className and superName resolve to the same type" }

        // string_ids must be sorted by UTF-16 code-unit order.
        val strings = listOf(classDesc, superDesc, initName, voidDesc).distinct().sorted()
        fun sIdx(s: String) = strings.indexOf(s)

        // type_ids must be sorted by their descriptor's string index.
        val types = listOf(classDesc, superDesc, voidDesc).distinct().sortedBy { sIdx(it) }
        fun tIdx(d: String) = types.indexOf(d)

        // Single proto ()V at index 0.
        val protoIdx = 0

        // method_ids must be sorted by (class_idx, name_idx, proto_idx).
        val mClass = MethodId(tIdx(classDesc), sIdx(initName), protoIdx)
        val mSuper = MethodId(tIdx(superDesc), sIdx(initName), protoIdx)
        val methods = listOf(mClass, mSuper)
            .sortedWith(compareBy({ it.classIdx }, { it.nameIdx }, { it.protoIdx }))
        val classCtorMethodIdx = methods.indexOf(mClass)
        val superCtorMethodIdx = methods.indexOf(mSuper)

        // --- Fixed-offset section layout (no field_ids, single proto/class_def) ---
        val stringIdsOff = HEADER_SIZE
        val typeIdsOff = stringIdsOff + strings.size * 4
        val protoIdsOff = typeIdsOff + types.size * 4
        val methodIdsOff = protoIdsOff + 1 * 12
        val classDefsOff = methodIdsOff + methods.size * 8
        val dataOff = classDefsOff + 1 * 32 // 4-byte aligned by construction

        // --- Data section items (build first so their offsets are known) ---
        val codeOff = dataOff
        val codeItem = buildCodeItem(superCtorMethodIdx)

        var pos = codeOff + codeItem.size
        val stringDataOffs = IntArray(strings.size)
        val stringDataBlob = ByteArrayOutputStream()
        for (i in strings.indices) {
            stringDataOffs[i] = pos
            val b = buildStringData(strings[i])
            stringDataBlob.write(b)
            pos += b.size
        }

        val classDataOff = pos
        val classData = buildClassData(classCtorMethodIdx, codeOff)
        pos += classData.size

        val mapPad = (4 - (pos % 4)) % 4
        pos += mapPad
        val mapOff = pos
        val mapList = buildMapList(
            stringIdsOff, strings.size,
            typeIdsOff, types.size,
            protoIdsOff,
            methodIdsOff, methods.size,
            classDefsOff,
            codeOff,
            stringDataOffs[0], strings.size,
            classDataOff,
            mapOff
        )
        pos += mapList.size

        val fileSize = pos

        // --- Assemble ---
        val buf = ByteBuffer.allocate(fileSize).order(ByteOrder.LITTLE_ENDIAN)

        // header (checksum + signature left as zero, filled in after)
        buf.put(DEX_MAGIC)
        buf.putInt(0)                 // checksum placeholder
        buf.put(ByteArray(20))        // signature placeholder
        buf.putInt(fileSize)
        buf.putInt(HEADER_SIZE)
        buf.putInt(ENDIAN_TAG)
        buf.putInt(0)                 // link_size
        buf.putInt(0)                 // link_off
        buf.putInt(mapOff)
        buf.putInt(strings.size)
        buf.putInt(stringIdsOff)
        buf.putInt(types.size)
        buf.putInt(typeIdsOff)
        buf.putInt(1)                 // proto_ids_size
        buf.putInt(protoIdsOff)
        buf.putInt(0)                 // field_ids_size
        buf.putInt(0)                 // field_ids_off
        buf.putInt(methods.size)
        buf.putInt(methodIdsOff)
        buf.putInt(1)                 // class_defs_size
        buf.putInt(classDefsOff)
        buf.putInt(fileSize - dataOff)
        buf.putInt(dataOff)
        check(buf.position() == stringIdsOff)

        // string_ids
        for (i in strings.indices) buf.putInt(stringDataOffs[i])
        check(buf.position() == typeIdsOff)

        // type_ids
        for (t in types) buf.putInt(sIdx(t))
        check(buf.position() == protoIdsOff)

        // proto_ids: one ()V
        buf.putInt(sIdx(voidDesc))    // shorty_idx
        buf.putInt(tIdx(voidDesc))    // return_type_idx
        buf.putInt(0)                 // parameters_off
        check(buf.position() == methodIdsOff)

        // method_ids
        for (m in methods) {
            buf.putShort(m.classIdx.toShort())
            buf.putShort(m.protoIdx.toShort())
            buf.putInt(m.nameIdx)
        }
        check(buf.position() == classDefsOff)

        // class_def
        buf.putInt(tIdx(classDesc))   // class_idx
        buf.putInt(ACC_PUBLIC)        // access_flags
        buf.putInt(tIdx(superDesc))   // superclass_idx
        buf.putInt(0)                 // interfaces_off
        buf.putInt(NO_INDEX)          // source_file_idx
        buf.putInt(0)                 // annotations_off
        buf.putInt(classDataOff)      // class_data_off
        buf.putInt(0)                 // static_values_off
        check(buf.position() == dataOff)

        // data section
        buf.put(codeItem)
        buf.put(stringDataBlob.toByteArray())
        check(buf.position() == classDataOff)
        buf.put(classData)
        repeat(mapPad) { buf.put(0) }
        check(buf.position() == mapOff)
        buf.put(mapList)
        check(buf.position() == fileSize)

        val out = buf.array()

        // signature = SHA-1 over everything after magic(8) + checksum(4) + signature(20) = offset 32
        val sha1 = MessageDigest.getInstance("SHA-1").digest(out.copyOfRange(32, fileSize))
        System.arraycopy(sha1, 0, out, 12, 20)

        // checksum = Adler-32 over everything after magic(8) + checksum(4) = offset 12
        val adler = Adler32()
        adler.update(out, 12, fileSize - 12)
        ByteBuffer.wrap(out, 8, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(adler.value.toInt())

        return out
    }

    private data class MethodId(val classIdx: Int, val nameIdx: Int, val protoIdx: Int)

    private fun toDescriptor(javaName: String): String = "L" + javaName.replace('.', '/') + ";"

    /** invoke-direct {p0}, superCtor; return-void */
    private fun buildCodeItem(superCtorMethodIdx: Int): ByteArray {
        val bb = ByteBuffer.allocate(16 + 8).order(ByteOrder.LITTLE_ENDIAN)
        bb.putShort(1) // registers_size (this)
        bb.putShort(1) // ins_size
        bb.putShort(1) // outs_size
        bb.putShort(0) // tries_size
        bb.putInt(0)   // debug_info_off
        bb.putInt(4)   // insns_size (16-bit code units)
        // invoke-direct {v0}, method@superCtor  (format 35c, 3 code units)
        bb.putShort(0x1070.toShort())            // op=0x70, A=1, G=0
        bb.putShort(superCtorMethodIdx.toShort()) // method_idx
        bb.putShort(0)                            // regs: C=v0, rest 0
        // return-void (format 10x, 1 code unit)
        bb.putShort(0x000e.toShort())
        return bb.array()
    }

    private fun buildStringData(s: String): ByteArray {
        val out = ByteArrayOutputStream()
        writeUleb128(out, s.length) // utf16_size = number of UTF-16 code units
        writeMutf8(out, s)
        out.write(0) // NUL terminator
        return out.toByteArray()
    }

    private fun buildClassData(ctorMethodIdx: Int, codeOff: Int): ByteArray {
        val out = ByteArrayOutputStream()
        writeUleb128(out, 0) // static_fields_size
        writeUleb128(out, 0) // instance_fields_size
        writeUleb128(out, 1) // direct_methods_size
        writeUleb128(out, 0) // virtual_methods_size
        // sole direct method: the constructor
        writeUleb128(out, ctorMethodIdx)                 // method_idx_diff (first entry)
        writeUleb128(out, ACC_PUBLIC or ACC_CONSTRUCTOR) // access_flags
        writeUleb128(out, codeOff)                       // code_off
        return out.toByteArray()
    }

    private fun buildMapList(
        stringIdsOff: Int, stringCount: Int,
        typeIdsOff: Int, typeCount: Int,
        protoIdsOff: Int,
        methodIdsOff: Int, methodCount: Int,
        classDefsOff: Int,
        codeOff: Int,
        stringDataOff: Int, stringDataCount: Int,
        classDataOff: Int,
        mapOff: Int
    ): ByteArray {
        // Items must be listed in ascending offset order.
        val items = listOf(
            Triple(TYPE_HEADER, 1, 0),
            Triple(TYPE_STRING_ID, stringCount, stringIdsOff),
            Triple(TYPE_TYPE_ID, typeCount, typeIdsOff),
            Triple(TYPE_PROTO_ID, 1, protoIdsOff),
            Triple(TYPE_METHOD_ID, methodCount, methodIdsOff),
            Triple(TYPE_CLASS_DEF, 1, classDefsOff),
            Triple(TYPE_CODE, 1, codeOff),
            Triple(TYPE_STRING_DATA, stringDataCount, stringDataOff),
            Triple(TYPE_CLASS_DATA, 1, classDataOff),
            Triple(TYPE_MAP_LIST, 1, mapOff)
        )
        val bb = ByteBuffer.allocate(4 + items.size * 12).order(ByteOrder.LITTLE_ENDIAN)
        bb.putInt(items.size)
        for ((type, size, offset) in items) {
            bb.putShort(type.toShort())
            bb.putShort(0) // unused
            bb.putInt(size)
            bb.putInt(offset)
        }
        return bb.array()
    }

    private fun writeUleb128(out: ByteArrayOutputStream, value: Int) {
        var v = value
        while (true) {
            val b = v and 0x7f
            v = v ushr 7
            if (v == 0) {
                out.write(b)
                break
            }
            out.write(b or 0x80)
        }
    }

    /** Modified UTF-8: NUL is two bytes; supplementary chars are encoded per UTF-16 surrogate. */
    private fun writeMutf8(out: ByteArrayOutputStream, s: String) {
        for (c in s) {
            val ch = c.code
            when {
                ch in 0x01..0x7f -> out.write(ch)
                ch == 0 || ch in 0x80..0x7ff -> {
                    out.write(0xc0 or (ch shr 6))
                    out.write(0x80 or (ch and 0x3f))
                }
                else -> {
                    out.write(0xe0 or (ch shr 12))
                    out.write(0x80 or ((ch shr 6) and 0x3f))
                    out.write(0x80 or (ch and 0x3f))
                }
            }
        }
    }
}
