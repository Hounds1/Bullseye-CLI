package io.bullseye.cli.enrollment;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.bullseye.cli.enrollment.EnrollmentClient.Invitation;
import io.bullseye.cli.enrollment.EnrollmentClient.Registration;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

final class EnrollmentBundle {
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int MAX_LOCAL_JSON_BYTES = 32_768;
    private static final List<String> BUNDLE_FILES =
            List.of("identity.p12", "trust.p12", "bullseye.properties", "tls.jvm", "enrollment.json");

    @FunctionalInterface
    interface RedeemOperation {
        Registration redeem(Invitation invite, UUID requestId, String csrPem)
                throws IOException, InterruptedException;
    }

    private record Pending(UUID requestId, EnrollmentIdentity identity) {}

    private EnrollmentBundle() {}

    static void install(Path output, Invitation invite, String baseConfig, RedeemOperation operation)
            throws IOException, InterruptedException {
        Path parent = output.getParent();
        if (parent == null || output.toString().indexOf('\n') >= 0 || output.toString().indexOf('\r') >= 0) {
            throw new IOException("Choose an output directory with a valid single-line path.");
        }
        Files.createDirectories(parent);
        Path pendingDirectory = parent.resolve("." + output.getFileName() + ".pending");
        preparePrivateDirectory(pendingDirectory);
        forceDirectory(parent);
        String inviteKey = inviteDigest(invite);

        try (FileChannel channel = FileChannel.open(pendingDirectory.resolve("lock"),
                StandardOpenOption.CREATE, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS);
                FileLock ignored = acquireLock(channel)) {
            Path requestFile = pendingDirectory.resolve("request.json");
            if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
                requireExistingBundle(output, inviteKey);
                clearCompletedRequest(requestFile, inviteKey);
                return;
            }

            Pending request = resumeOrCreate(requestFile, invite, inviteKey);
            Registration registration = operation.redeem(invite, request.requestId(), request.identity().csrPem());
            writeBundle(output, request.identity(), registration, baseConfig, inviteKey);
            clearCompletedRequest(requestFile, inviteKey);
        }
    }

    private static FileLock acquireLock(FileChannel channel) throws IOException {
        try {
            FileLock lock = channel.tryLock();
            if (lock != null) {
                return lock;
            }
        } catch (OverlappingFileLockException busy) {
            // The same output is already being enrolled by this JVM.
        }
        throw new IOException("An enrollment for this output directory is already running.");
    }

    private static void preparePrivateDirectory(Path directory) throws IOException {
        try {
            if (hasPosixPermissions(directory.getParent())) {
                Files.createDirectory(directory,
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            } else {
                Files.createDirectory(directory);
            }
        } catch (FileAlreadyExistsException exists) {
            // A previous attempt may have saved the request here.
        }
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Enrollment resume path must be a directory.");
        }
        if (hasPosixPermissions(directory) && Files.getPosixFilePermissions(directory).stream()
                .anyMatch(permission -> !permission.name().startsWith("OWNER_"))) {
            throw new IOException("Enrollment resume directory must be private to its owner.");
        }
    }

    private static boolean hasPosixPermissions(Path path) {
        return Files.getFileAttributeView(path, PosixFileAttributeView.class) != null;
    }

    private static Pending resumeOrCreate(Path file, Invitation invite, String inviteKey) throws IOException {
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            JsonNode saved = readLocalJson(file);
            if (!inviteKey.equals(saved.path("inviteDigest").textValue())) {
                throw new IOException("A different invitation already has a pending request for this output.");
            }
            try {
                UUID requestId = UUID.fromString(requiredText(saved, "requestId"));
                byte[] privateKey = Base64.getDecoder().decode(requiredText(saved, "privateKey"));
                try {
                    byte[] publicKey = Base64.getDecoder().decode(requiredText(saved, "publicKey"));
                    return new Pending(requestId, EnrollmentIdentity.restore(
                            privateKey, publicKey, requiredText(saved, "csrPem")));
                } finally {
                    Arrays.fill(privateKey, (byte) 0);
                }
            } catch (IllegalArgumentException invalid) {
                throw new IOException("Invalid enrollment resume data.");
            }
        }

        var request = new Pending(UUID.randomUUID(), EnrollmentIdentity.generate(invite.nodeId()));
        var encoder = Base64.getEncoder();
        byte[] privateKey = request.identity().privateKey().getEncoded();
        try {
            var saved = JSON.createObjectNode().put("schemaVersion", 1)
                    .put("inviteDigest", inviteKey)
                    .put("requestId", request.requestId().toString())
                    .put("privateKey", encoder.encodeToString(privateKey))
                    .put("publicKey", encoder.encodeToString(request.identity().publicKey().getEncoded()))
                    .put("csrPem", request.identity().csrPem());
            saveRequest(file, JSON.writeValueAsBytes(saved));
        } finally {
            Arrays.fill(privateKey, (byte) 0);
        }
        return request;
    }

    private static void saveRequest(Path file, byte[] contents) throws IOException {
        Path temporary = Files.createTempFile(file.getParent(), ".request-", ".tmp");
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(contents);
                while (buffer.hasRemaining()) {
                    channel.write(buffer);
                }
                channel.force(true);
            }
            Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE);
            forceDirectory(file.getParent());
        } finally {
            Arrays.fill(contents, (byte) 0);
            Files.deleteIfExists(temporary);
        }
    }

    private static JsonNode readLocalJson(Path file) throws IOException {
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("Enrollment state must be a regular file.");
        }
        try (var input = Files.newInputStream(file)) {
            byte[] bytes = input.readNBytes(MAX_LOCAL_JSON_BYTES + 1);
            try {
                if (bytes.length <= MAX_LOCAL_JSON_BYTES) {
                    JsonNode value = JSON.readTree(bytes);
                    if (value != null && value.isObject() && value.path("schemaVersion").isIntegralNumber()
                            && value.path("schemaVersion").canConvertToInt()
                            && value.path("schemaVersion").intValue() == 1) {
                        return value;
                    }
                }
            } catch (JsonProcessingException invalid) {
                // Report the failure without echoing the contents.
            } finally {
                Arrays.fill(bytes, (byte) 0);
            }
        }
        throw new IOException("Invalid local enrollment state.");
    }

    private static String requiredText(JsonNode node, String field) {
        String value = node.path(field).textValue();
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Required enrollment field missing");
        }
        return value;
    }

    private static void requireExistingBundle(Path output, String inviteKey) throws IOException {
        if (!Files.isDirectory(output, LinkOption.NOFOLLOW_LINKS)
                || BUNDLE_FILES.stream().anyMatch(
                        file -> !Files.isRegularFile(output.resolve(file), LinkOption.NOFOLLOW_LINKS))
                || !inviteKey.equals(readLocalJson(output.resolve("enrollment.json")).path("inviteDigest").textValue())) {
            throw new IOException("Output already exists. Choose a new directory for a different enrollment.");
        }
    }

    private static void clearCompletedRequest(Path file, String inviteKey) throws IOException {
        if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        try {
            if (!inviteKey.equals(readLocalJson(file).path("inviteDigest").textValue())) {
                throw new IOException("Pending request belongs to a different invitation.");
            }
            Files.delete(file);
        } catch (IOException failure) {
            throw new IOException("Enrollment bundle is ready, but its pending request could not be cleared.", failure);
        }
    }

    private static void writeBundle(Path output, EnrollmentIdentity identity, Registration registration,
            String baseConfig, String inviteKey) throws IOException {
        Path parent = output.getParent();
        Path staging = hasPosixPermissions(parent)
                ? Files.createTempDirectory(parent, ".bullseye-enroll-",
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
                : Files.createTempDirectory(parent, ".bullseye-enroll-");
        try {
            byte[] secret = new byte[24];
            RANDOM.nextBytes(secret);
            char[] password = HexFormat.of().formatHex(secret).toCharArray();
            Arrays.fill(secret, (byte) 0);
            try {
                identity.writeStores(staging, registration.certificateChainPem(),
                        registration.cccServerCaPem(), password);
                Files.writeString(staging.resolve("tls.jvm"), jvmOptions(output, new String(password)));
            } finally {
                Arrays.fill(password, '\0');
            }
            Files.writeString(staging.resolve("bullseye.properties"), properties(baseConfig, registration));
            Files.write(staging.resolve("enrollment.json"), JSON.writeValueAsBytes(
                    JSON.createObjectNode().put("schemaVersion", 1)
                            .put("nodeId", registration.nodeId()).put("inviteDigest", inviteKey)));
            for (String name : BUNDLE_FILES) {
                Path file = staging.resolve(name);
                if (hasPosixPermissions(file)) {
                    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
                }
                try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
                    channel.force(true);
                }
            }
            forceDirectory(staging);
            if (Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("Output was created during enrollment. The original request is saved for retry.");
            }
            Files.move(staging, output, StandardCopyOption.ATOMIC_MOVE);
            forceDirectory(parent);
        } catch (IOException | RuntimeException failure) {
            try {
                for (String name : BUNDLE_FILES) {
                    Files.deleteIfExists(staging.resolve(name));
                }
                Files.deleteIfExists(staging);
            } catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw failure;
        }
    }

    private static void forceDirectory(Path directory) {
        try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
            channel.force(true);
        } catch (IOException | UnsupportedOperationException unsupported) {
            // Directory syncing depends on the filesystem provider.
        }
    }

    private static String properties(String baseConfig, Registration registration) {
        String prefix = baseConfig.isEmpty() ? "" : baseConfig + "\n\n";
        return prefix + """
                # CCC connection installed by Bullseye CLI
                bullseye.ccc.enabled=true
                bullseye.ccc.host=%s
                bullseye.ccc.port=%d
                bullseye.ccc.node-id=%s
                """.formatted(registration.cccHost(), registration.cccPort(), registration.nodeId());
    }

    private static String jvmOptions(Path output, String password) {
        return String.join("\n",
                jvmArgument("keyStore", output.resolve("identity.p12").toString()),
                jvmArgument("keyStoreType", "PKCS12"),
                jvmArgument("keyStorePassword", password),
                jvmArgument("trustStore", output.resolve("trust.p12").toString()),
                jvmArgument("trustStoreType", "PKCS12"),
                jvmArgument("trustStorePassword", password)) + "\n";
    }

    private static String jvmArgument(String name, String value) {
        return "\"-Djavax.net.ssl." + name + "=" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String inviteDigest(Invitation invite) {
        String key = String.join("\0", invite.nodeId(), invite.enrollmentUrl().toASCIIString(),
                invite.serverCaPem(), invite.expiresAt().toString(), invite.code());
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(key.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException unavailable) {
            throw new IllegalStateException("SHA-256 is unavailable", unavailable);
        }
    }
}
