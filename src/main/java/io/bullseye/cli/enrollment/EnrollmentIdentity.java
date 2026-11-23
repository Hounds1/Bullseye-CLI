package io.bullseye.cli.enrollment;

import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Local enrollment key material, retained unchanged while retrying an enrollment request. */
record EnrollmentIdentity(PrivateKey privateKey, PublicKey publicKey, String csrPem) {
    private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    private static final String CSR_BEGIN = "-----BEGIN CERTIFICATE REQUEST-----";
    private static final String CSR_END = "-----END CERTIFICATE REQUEST-----";

    static EnrollmentIdentity generate(String nodeId) throws IOException {
        if (nodeId == null || !nodeId.matches("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")) {
            throw new IOException("Invalid enrollment node ID");
        }
        try {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            var pair = generator.generateKeyPair();
            var subject = new X500NameBuilder(BCStyle.INSTANCE)
                    .addRDN(BCStyle.CN, new DERUTF8String(nodeId)).build();
            var signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(pair.getPrivate());
            var request = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic()).build(signer);
            String pem = CSR_BEGIN + "\n"
                    + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(request.getEncoded())
                    + "\n" + CSR_END + "\n";
            return new EnrollmentIdentity(pair.getPrivate(), pair.getPublic(), pem);
        } catch (GeneralSecurityException | OperatorCreationException failure) {
            throw new IOException("Unable to generate enrollment key material", failure);
        }
    }

    static EnrollmentIdentity restore(byte[] privateKey, byte[] publicKey, String csrPem)
            throws IOException {
        if (privateKey == null || publicKey == null || csrPem == null) {
            throw new IOException("Enrollment retry key material is incomplete");
        }
        try {
            var factory = KeyFactory.getInstance("EC");
            PrivateKey restoredPrivate = factory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            PublicKey restoredPublic = factory.generatePublic(new X509EncodedKeySpec(publicKey));
            requireP256(SubjectPublicKeyInfo.getInstance(restoredPublic.getEncoded()));
            requireMatchingKey(restoredPrivate, restoredPublic);
            var request = new PKCS10CertificationRequest(decodeCsr(csrPem));
            requireP256(request.getSubjectPublicKeyInfo());
            if (!MessageDigest.isEqual(restoredPublic.getEncoded(),
                    request.getSubjectPublicKeyInfo().getEncoded())
                    || !X9ObjectIdentifiers.ecdsa_with_SHA256.equals(
                            request.getSignatureAlgorithm().getAlgorithm())
                    || !request.isSignatureValid(
                            new JcaContentVerifierProviderBuilder().build(restoredPublic))) {
                throw new IOException("Enrollment retry CSR does not match its local key pair");
            }
            return new EnrollmentIdentity(restoredPrivate, restoredPublic, csrPem);
        } catch (GeneralSecurityException | OperatorCreationException | PKCSException
                | IllegalArgumentException failure) {
            throw new IOException("Invalid enrollment retry key material", failure);
        }
    }

    void writeStores(Path directory, String certificateChainPem, String serverCaPem, char[] password)
            throws IOException {
        if (password == null) {
            throw new IOException("A keystore password is required");
        }
        List<X509Certificate> chain = EnrollmentClient.certificates(certificateChainPem);
        List<X509Certificate> authorities = EnrollmentClient.certificates(serverCaPem);
        try {
            requireP256(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
            requireMatchingKey(privateKey, publicKey);
            validateClientChain(chain, publicKey);
            if (authorities.isEmpty()) {
                throw new IOException("Enrollment response contains no server trust anchors");
            }
            Date now = new Date();
            for (X509Certificate authority : authorities) {
                validateServerAnchor(authority, now);
            }

            KeyStore identity = KeyStore.getInstance("PKCS12");
            identity.load(null, password);
            identity.setKeyEntry("core", privateKey, password, chain.toArray(X509Certificate[]::new));
            KeyStore trust = KeyStore.getInstance("PKCS12");
            trust.load(null, password);
            for (int index = 0; index < authorities.size(); index++) {
                trust.setCertificateEntry("server-ca-" + (index + 1), authorities.get(index));
            }
            byte[] identityBytes = encode(identity, password);
            byte[] trustBytes = encode(trust, password);
            Path identityFile = directory.resolve("identity.p12");
            writeNew(identityFile, identityBytes);
            try {
                writeNew(directory.resolve("trust.p12"), trustBytes);
            } catch (IOException | RuntimeException failure) {
                try {
                    Files.deleteIfExists(identityFile);
                } catch (IOException cleanup) {
                    failure.addSuppressed(cleanup);
                }
                throw failure;
            }
        } catch (GeneralSecurityException failure) {
            throw new IOException("Unable to validate or store the enrolled identity", failure);
        }
    }

    private static void validateClientChain(List<X509Certificate> chain, PublicKey publicKey)
            throws GeneralSecurityException, IOException {
        if (chain.size() < 2 || new HashSet<>(chain).size() != chain.size()) {
            throw new IOException("Expected one leaf-first client certificate chain with its issuer");
        }
        X509Certificate leaf = chain.getFirst();
        boolean[] keyUsage = leaf.getKeyUsage();
        List<String> purposes = leaf.getExtendedKeyUsage();
        if (!MessageDigest.isEqual(leaf.getPublicKey().getEncoded(), publicKey.getEncoded())
                || leaf.getBasicConstraints() >= 0 || keyUsage == null || keyUsage.length == 0
                || !keyUsage[0] || purposes == null || !purposes.contains(CLIENT_AUTH)) {
            throw new IOException("Issued certificate is not a client identity for the local key");
        }

        Date now = new Date();
        for (int index = 0; index < chain.size(); index++) {
            X509Certificate certificate = chain.get(index);
            certificate.checkValidity(now);
            if (certificate.hasUnsupportedCriticalExtension()) {
                throw new IOException("Unsupported critical certificate extension");
            }
            if (index > 0) {
                requireAuthority(certificate, now);
            }
            if (index + 1 < chain.size()) {
                X509Certificate issuer = chain.get(index + 1);
                if (!certificate.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
                    throw new IOException("Client certificate chain is not in leaf-first issuer order");
                }
                certificate.verify(issuer.getPublicKey());
            }
        }
        X509Certificate anchor = chain.getLast();
        if (anchor.getSubjectX500Principal().equals(anchor.getIssuerX500Principal())) {
            anchor.verify(anchor.getPublicKey());
        }
        var path = CertificateFactory.getInstance("X.509")
                .generateCertPath(chain.subList(0, chain.size() - 1));
        var parameters = new PKIXParameters(Set.of(new TrustAnchor(anchor, null)));
        parameters.setDate(now);
        parameters.setRevocationEnabled(false);
        CertPathValidator.getInstance("PKIX").validate(path, parameters);
    }

    private static void requireAuthority(X509Certificate certificate, Date now)
            throws GeneralSecurityException, IOException {
        certificate.checkValidity(now);
        boolean[] keyUsage = certificate.getKeyUsage();
        if (certificate.getBasicConstraints() < 0
                || (keyUsage != null && (keyUsage.length <= 5 || !keyUsage[5]))
                || certificate.hasUnsupportedCriticalExtension()) {
            throw new IOException("Enrollment trust material contains an invalid CA certificate");
        }
    }

    private static void validateServerAnchor(X509Certificate certificate, Date now)
            throws GeneralSecurityException, IOException {
        boolean selfIssued = certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal());
        if (certificate.getBasicConstraints() >= 0) {
            requireAuthority(certificate, now);
        } else {
            certificate.checkValidity(now);
            var purposes = certificate.getExtendedKeyUsage();
            if (!selfIssued || certificate.hasUnsupportedCriticalExtension()
                    || (purposes != null && !purposes.contains("1.3.6.1.5.5.7.3.1"))) {
                throw new IOException("Enrollment trust material contains an invalid server certificate");
            }
        }
        if (selfIssued) {
            certificate.verify(certificate.getPublicKey());
        }
    }

    private static void requireP256(SubjectPublicKeyInfo publicKey) throws IOException {
        var algorithm = publicKey.getAlgorithm();
        if (!X9ObjectIdentifiers.id_ecPublicKey.equals(algorithm.getAlgorithm())
                || !X9ObjectIdentifiers.prime256v1.equals(algorithm.getParameters())) {
            throw new IOException("Enrollment requires a P-256 key");
        }
    }

    private static void requireMatchingKey(PrivateKey privateKey, PublicKey publicKey)
            throws GeneralSecurityException {
        byte[] challenge = "bullseye-cli enrollment key check".getBytes(StandardCharsets.US_ASCII);
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(challenge);
        byte[] signed = signature.sign();
        signature.initVerify(publicKey);
        signature.update(challenge);
        if (!signature.verify(signed)) {
            throw new GeneralSecurityException("Enrollment private and public keys do not match");
        }
    }

    private static byte[] decodeCsr(String pem) throws IOException {
        String document = pem.strip();
        if (!document.startsWith(CSR_BEGIN) || !document.endsWith(CSR_END)) {
            throw new IOException("Expected one enrollment CSR in PEM format");
        }
        String body = document.substring(CSR_BEGIN.length(), document.length() - CSR_END.length());
        return Base64.getDecoder().decode(body.replaceAll("\\s", ""));
    }

    private static byte[] encode(KeyStore store, char[] password)
            throws GeneralSecurityException, IOException {
        var output = new ByteArrayOutputStream();
        store.store(output, password);
        return output.toByteArray();
    }

    private static void writeNew(Path file, byte[] contents) throws IOException {
        // The caller owns this private temporary directory and publishes it only after both stores exist.
        try (var channel = FileChannel.open(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            try {
                var bytes = ByteBuffer.wrap(contents);
                while (bytes.hasRemaining()) {
                    channel.write(bytes);
                }
                channel.force(true);
            } catch (IOException | RuntimeException failure) {
                try {
                    channel.close();
                    Files.deleteIfExists(file);
                } catch (IOException cleanup) {
                    failure.addSuppressed(cleanup);
                }
                throw failure;
            }
        }
    }
}
