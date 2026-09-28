package top.nkbe.nza.sign

import java.security.PrivateKey
import java.security.cert.X509Certificate

interface SignatureKey {
    val privateKey: PrivateKey
    val certificates: Array<X509Certificate>
    val certificate: X509Certificate
        get() = certificates[0]
}

class GenericSignatureKey(
    override val privateKey: PrivateKey,
    override val certificates: Array<X509Certificate>
) : SignatureKey {
    constructor(privateKey: PrivateKey, certificate: X509Certificate) : this(
        privateKey,
        arrayOf(certificate)
    )
}

