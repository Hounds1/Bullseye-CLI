package io.bullseye.cli.enrollment;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

class EnrollmentIdentityTest {
    private static final char[] PASSWORD = "fixture-only".toCharArray();
    private static final AtomicLong SERIAL = new AtomicLong();
    private static final X500Name ROOT = new X500Name("CN=Client Root");
    private static final X500Name INTERMEDIATE = new X500Name("CN=Client Issuer");
    private static final X500Name NODE = new X500Name("CN=edge-01");

    @TempDir
    Path directory;

    @Test
    void generatesP256SignedCsrAndRestoresTheSameIdentity() throws Exception {
        var identity = EnrollmentIdentity.generate("edge-01");
        var request = new PKCS10CertificationRequest(csrDer(identity.csrPem()));
        assertEquals(X9ObjectIdentifiers.id_ecPublicKey,
                request.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm());
        assertEquals(X9ObjectIdentifiers.prime256v1,
                request.getSubjectPublicKeyInfo().getAlgorithm().getParameters());
        assertEquals(X9ObjectIdentifiers.ecdsa_with_SHA256,
                request.getSignatureAlgorithm().getAlgorithm());
        assertEquals(NODE, request.getSubject());
        assertTrue(request.isSignatureValid(
                new JcaContentVerifierProviderBuilder().build(identity.publicKey())));

        var restored = EnrollmentIdentity.restore(identity.privateKey().getEncoded(),
                identity.publicKey().getEncoded(), identity.csrPem());
        assertArrayEquals(identity.privateKey().getEncoded(), restored.privateKey().getEncoded());
        assertArrayEquals(identity.publicKey().getEncoded(), restored.publicKey().getEncoded());
        assertEquals(identity.csrPem(), restored.csrPem());
    }

    @Test
    void refusesMismatchedKeysCsrAndSignatureWhenResuming() throws Exception {
        var first = EnrollmentIdentity.generate("edge-01");
        var other = EnrollmentIdentity.generate("edge-02");
        assertThrows(IOException.class, () -> EnrollmentIdentity.restore(
                other.privateKey().getEncoded(), first.publicKey().getEncoded(), first.csrPem()));
        assertThrows(IOException.class, () -> EnrollmentIdentity.restore(
                first.privateKey().getEncoded(), first.publicKey().getEncoded(), other.csrPem()));
        String forged = csr(first.publicKey(), other.privateKey());
        assertThrows(IOException.class, () -> EnrollmentIdentity.restore(
                first.privateKey().getEncoded(), first.publicKey().getEncoded(), forged));
        assertThrows(IOException.class, () -> EnrollmentIdentity.restore(
                new byte[] {1, 2, 3}, first.publicKey().getEncoded(), first.csrPem()));
        assertThrows(IOException.class, () -> EnrollmentIdentity.restore(
                first.privateKey().getEncoded(), first.publicKey().getEncoded(), first.csrPem() + first.csrPem()));
        var unsupported = keys("secp384r1");
        assertThrows(IOException.class, () -> EnrollmentIdentity.restore(
                unsupported.getPrivate().getEncoded(), unsupported.getPublic().getEncoded(),
                csr(unsupported.getPublic(), unsupported.getPrivate())));
    }

    @Test
    void writesClientKeyChainAndSeparateAuthenticatedServerTrustStore() throws Exception {
        var identity = EnrollmentIdentity.generate("edge-01");
        var rootKeys = keys("secp256r1");
        var issuerKeys = keys("secp256r1");
        var serverKeys = keys("secp256r1");
        X509Certificate root = authority(ROOT, ROOT, rootKeys.getPublic(), rootKeys.getPrivate());
        X509Certificate issuer = authority(
                INTERMEDIATE, ROOT, issuerKeys.getPublic(), rootKeys.getPrivate());
        X509Certificate leaf = certificate(NODE, INTERMEDIATE, identity.publicKey(),
                issuerKeys.getPrivate(), false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                Instant.now().plus(Duration.ofDays(10)));
        var serverName = new X500Name("CN=Server Root");
        X509Certificate serverRoot = authority(
                serverName, serverName, serverKeys.getPublic(), serverKeys.getPrivate());

        identity.writeStores(directory, pem(leaf, issuer, root), pem(serverRoot), PASSWORD);

        KeyStore identityStore = readStore("identity.p12");
        assertEquals(1, identityStore.size());
        assertTrue(identityStore.isKeyEntry("core"));
        assertArrayEquals(identity.privateKey().getEncoded(),
                identityStore.getKey("core", PASSWORD).getEncoded());
        assertArrayEquals(new X509Certificate[] {leaf, issuer, root}, identityStore.getCertificateChain("core"));
        KeyStore trustStore = readStore("trust.p12");
        assertEquals(1, trustStore.size());
        assertTrue(trustStore.isCertificateEntry("server-ca-1"));
        assertEquals(serverRoot, trustStore.getCertificate("server-ca-1"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"different-key", "ca", "missing-key-usage", "wrong-key-usage",
            "missing-eku", "server-only", "expired", "wrong-signature"})
    void rejectsInvalidIssuedLeafBeforeWritingAnyFiles(String defect) throws Exception {
        var identity = EnrollmentIdentity.generate("edge-01");
        var rootKeys = keys("secp256r1");
        var otherKeys = keys("secp256r1");
        X509Certificate root = authority(ROOT, ROOT, rootKeys.getPublic(), rootKeys.getPrivate());
        PublicKey leafKey = defect.equals("different-key") ? otherKeys.getPublic() : identity.publicKey();
        PrivateKey signer = defect.equals("wrong-signature") ? otherKeys.getPrivate() : rootKeys.getPrivate();
        Integer usage = switch (defect) {
            case "missing-key-usage" -> null;
            case "wrong-key-usage" -> KeyUsage.keyEncipherment;
            default -> KeyUsage.digitalSignature;
        };
        KeyPurposeId purpose = switch (defect) {
            case "missing-eku" -> null;
            case "server-only" -> KeyPurposeId.id_kp_serverAuth;
            default -> KeyPurposeId.id_kp_clientAuth;
        };
        Instant expiry = defect.equals("expired")
                ? Instant.now().minus(Duration.ofHours(1)) : Instant.now().plus(Duration.ofDays(10));
        X509Certificate leaf = certificate(
                NODE, ROOT, leafKey, signer, defect.equals("ca"), usage, purpose, expiry);

        assertThrows(IOException.class,
                () -> identity.writeStores(directory, pem(leaf, root), pem(root), PASSWORD));
        assertFalse(Files.exists(directory.resolve("identity.p12")));
        assertFalse(Files.exists(directory.resolve("trust.p12")));
    }

    @Test
    void rejectsReorderedIncompleteAndUnrelatedChains() throws Exception {
        var identity = EnrollmentIdentity.generate("edge-01");
        var rootKeys = keys("secp256r1");
        var issuerKeys = keys("secp256r1");
        X509Certificate root = authority(ROOT, ROOT, rootKeys.getPublic(), rootKeys.getPrivate());
        X509Certificate issuer = authority(
                INTERMEDIATE, ROOT, issuerKeys.getPublic(), rootKeys.getPrivate());
        X509Certificate leaf = certificate(NODE, INTERMEDIATE, identity.publicKey(),
                issuerKeys.getPrivate(), false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                Instant.now().plus(Duration.ofDays(10)));

        for (String chain : List.of(pem(root, issuer, leaf), pem(leaf), pem(leaf, root),
                pem(leaf, root, issuer), pem(leaf, issuer, issuer, root))) {
            assertThrows(IOException.class, () -> identity.writeStores(directory, chain, pem(root), PASSWORD));
        }
        assertFalse(Files.exists(directory.resolve("identity.p12")));
    }

    @Test
    void rejectsNonCaServerTrustMaterial() throws Exception {
        var identity = EnrollmentIdentity.generate("edge-01");
        var rootKeys = keys("secp256r1");
        X509Certificate root = authority(ROOT, ROOT, rootKeys.getPublic(), rootKeys.getPrivate());
        X509Certificate leaf = certificate(NODE, ROOT, identity.publicKey(), rootKeys.getPrivate(),
                false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                Instant.now().plus(Duration.ofDays(10)));

        assertThrows(IOException.class,
                () -> identity.writeStores(directory, pem(leaf, root), pem(leaf), PASSWORD));
        assertFalse(Files.exists(directory.resolve("identity.p12")));
        assertFalse(Files.exists(directory.resolve("trust.p12")));
    }

    @Test
    void preservesExistingFilesAndRemovesNewIdentityIfTrustWriteFails() throws Exception {
        var identity = EnrollmentIdentity.generate("edge-01");
        var rootKeys = keys("secp256r1");
        X509Certificate root = authority(ROOT, ROOT, rootKeys.getPublic(), rootKeys.getPrivate());
        X509Certificate leaf = certificate(NODE, ROOT, identity.publicKey(), rootKeys.getPrivate(),
                false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                Instant.now().plus(Duration.ofDays(10)));
        Path trustFile = directory.resolve("trust.p12");
        Files.writeString(trustFile, "existing trust material");

        assertThrows(IOException.class,
                () -> identity.writeStores(directory, pem(leaf, root), pem(root), PASSWORD));
        assertEquals("existing trust material", Files.readString(trustFile));
        assertFalse(Files.exists(directory.resolve("identity.p12")));
    }

    private KeyStore readStore(String name) throws Exception {
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(directory.resolve(name))) {
            store.load(input, PASSWORD);
        }
        return store;
    }

    private static KeyPair keys(String curve) throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(curve));
        return generator.generateKeyPair();
    }

    private static X509Certificate authority(
            X500Name subject, X500Name issuer, PublicKey publicKey, PrivateKey signer) throws Exception {
        return certificate(subject, issuer, publicKey, signer, true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign, null, Instant.now().plus(Duration.ofDays(120)));
    }

    private static X509Certificate certificate(X500Name subject, X500Name issuer, PublicKey publicKey,
            PrivateKey signer, boolean ca, Integer usage, KeyPurposeId purpose, Instant expiry)
            throws Exception {
        var builder = new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(SERIAL.incrementAndGet()),
                Date.from(Instant.now().minus(Duration.ofDays(1))), Date.from(expiry), subject, publicKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        if (usage != null) {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(usage));
        }
        if (purpose != null) {
            builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purpose));
        }
        return new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withECDSA").build(signer)));
    }

    private static String pem(X509Certificate... certificates) throws Exception {
        StringBuilder pem = new StringBuilder();
        for (X509Certificate certificate : certificates) {
            pem.append("-----BEGIN CERTIFICATE-----\n")
                    .append(Base64.getMimeEncoder(64, new byte[] {'\n'})
                            .encodeToString(certificate.getEncoded()))
                    .append("\n-----END CERTIFICATE-----\n");
        }
        return pem.toString();
    }

    private static String csr(PublicKey publicKey, PrivateKey signer) throws Exception {
        var request = new JcaPKCS10CertificationRequestBuilder(NODE, publicKey)
                .build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer));
        return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(request.getEncoded())
                + "\n-----END CERTIFICATE REQUEST-----\n";
    }

    private static byte[] csrDer(String pem) {
        return Base64.getDecoder().decode(pem.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "").replaceAll("\\s", ""));
    }
}
