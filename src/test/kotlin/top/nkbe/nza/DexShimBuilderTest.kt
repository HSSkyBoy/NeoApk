package top.nkbe.nza

import org.jf.dexlib2.AccessFlags
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.dexbacked.DexBackedDexFile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import top.nkbe.nza.dex.DexShimBuilder
import java.security.MessageDigest
import java.util.zip.Adler32

class DexShimBuilderTest {

    private val stub = "top.nkbe.npatch.metaloader.LSPAppComponentFactoryStub"

    private fun parse(bytes: ByteArray): DexBackedDexFile =
        DexBackedDexFile(Opcodes.getDefault(), bytes)

    @Test
    fun buildsSingleClassWithReparentedSuperAndDefaultCtor() {
        val bytes = DexShimBuilder.buildFactoryShim("com.host.RealFactory", stub)
        val dex = parse(bytes)

        val classes = dex.classes.toList()
        assertEquals(1, classes.size)
        val cls = classes.single()
        assertEquals("Lcom/host/RealFactory;", cls.type)
        assertEquals("Ltop/nkbe/npatch/metaloader/LSPAppComponentFactoryStub;", cls.superclass)
        assertTrue(AccessFlags.PUBLIC.isSet(cls.accessFlags))

        // Exactly one method (the constructor), no fields.
        assertEquals(0, cls.fields.count())
        val methods = cls.methods.toList()
        assertEquals(1, methods.size)
        val ctor = methods.single()
        assertEquals("<init>", ctor.name)
        assertEquals("V", ctor.returnType)
        assertTrue(ctor.parameterTypes.isEmpty())
        assertTrue(AccessFlags.CONSTRUCTOR.isSet(ctor.accessFlags))
    }

    @Test
    fun checksumAndSignatureMatchRecomputation() {
        val bytes = DexShimBuilder.buildFactoryShim("a.B", stub)

        // signature = SHA-1 over bytes[32..]
        val expectedSig = MessageDigest.getInstance("SHA-1").digest(bytes.copyOfRange(32, bytes.size))
        val actualSig = bytes.copyOfRange(12, 32)
        assertTrue(expectedSig.contentEquals(actualSig))

        // checksum = Adler-32 over bytes[12..] (little-endian uint at offset 8)
        val adler = Adler32()
        adler.update(bytes, 12, bytes.size - 12)
        val expected = adler.value.toInt()
        val actual = (bytes[8].toInt() and 0xff) or
            ((bytes[9].toInt() and 0xff) shl 8) or
            ((bytes[10].toInt() and 0xff) shl 16) or
            ((bytes[11].toInt() and 0xff) shl 24)
        assertEquals(expected, actual)
    }

    @Test
    fun handlesDeepPackagesInnerClassesAndShortLongNames() {
        // className, expected descriptor
        val samples = listOf(
            "p.q.r.s.t.u.DeeplyNested" to "Lp/q/r/s/t/u/DeeplyNested;",
            "com.example.Outer\$Inner" to "Lcom/example/Outer\$Inner;",
            "x.Y" to "Lx/Y;",
            ("com." + "seg.".repeat(30) + "End") to ("Lcom/" + "seg/".repeat(30) + "End;")
        )
        for ((name, desc) in samples) {
            val dex = parse(DexShimBuilder.buildFactoryShim(name, stub))
            val cls = dex.classes.single()
            assertEquals(desc, cls.type)
            assertEquals("Ltop/nkbe/npatch/metaloader/LSPAppComponentFactoryStub;", cls.superclass)
            assertEquals(1, cls.methods.count())
        }
    }
}
