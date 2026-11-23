package io.bullseye.cli.enrollment;

import io.bullseye.cli.enrollment.EnrollmentClient.Invitation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EnrollmentBundleTest {
    @TempDir
    Path directory;

    @Test
    void retriesTheSameRequestAndCsrWithoutSavingTheInvitationCode() throws Exception {
        Path output = directory.resolve("enrolled");
        Path pending = directory.resolve(".enrolled.pending/request.json");
        String fingerprint = EnrollmentBundle.prepare(output, "edge-01");
        Invitation invite = invite("A", fingerprint);
        var requestId = new AtomicReference<UUID>();
        var csr = new AtomicReference<String>();

        assertThrows(IOException.class, () -> EnrollmentBundle.install(output, invite, "",
                (sentInvite, sentId, sentCsr) -> {
                    assertTrue(Files.isRegularFile(pending));
                    assertEquals(invite, sentInvite);
                    requestId.set(sentId);
                    csr.set(sentCsr);
                    throw new IOException("Response unavailable");
                }));
        assertFalse(Files.exists(output));
        assertFalse(Files.readString(pending).contains(invite.code()));

        IOException failure = assertThrows(IOException.class, () -> EnrollmentBundle.install(
                output, invite, "", (sentInvite, sentId, sentCsr) -> {
                    assertEquals(requestId.get(), sentId);
                    assertEquals(csr.get(), sentCsr);
                    throw new IOException("Response still unavailable");
                }));
        assertEquals("Response still unavailable", failure.getMessage());
        assertFalse(Files.exists(output));

        IOException different = assertThrows(IOException.class, () -> EnrollmentBundle.install(
                output, invite("B", fingerprint), "", (sentInvite, sentId, sentCsr) -> {
                    throw new AssertionError("A different invite reached the API");
                }));
        assertTrue(different.getMessage().contains("different invitation"));
    }

    @Test
    void prepareReusesTheKeyAndRejectsAnInvitationBoundToAnotherKeyLocally() throws Exception {
        Path output = directory.resolve("enrolled");
        String fingerprint = EnrollmentBundle.prepare(output, "edge-01");
        String otherFingerprint = EnrollmentBundle.prepare(directory.resolve("other"), "edge-01");

        assertTrue(fingerprint.matches("[a-f0-9]{64}"));
        assertEquals(fingerprint, EnrollmentBundle.prepare(output, "edge-01"));
        assertThrows(IOException.class, () -> EnrollmentBundle.prepare(output, "edge-02"));

        IOException mismatch = assertThrows(IOException.class, () -> EnrollmentBundle.install(
                output, invite("A", otherFingerprint), "", (sentInvite, sentId, sentCsr) -> {
                    throw new AssertionError("An invitation for another key reached the API");
                }));
        assertTrue(mismatch.getMessage().contains("does not match"));

        IOException sent = assertThrows(IOException.class, () -> EnrollmentBundle.install(
                output, invite("A", fingerprint), "", (sentInvite, sentId, sentCsr) -> {
                    throw new IOException("Request sent");
                }));
        assertEquals("Request sent", sent.getMessage());
    }

    @Test
    void preservesAnExistingOutputDirectoryWithoutSendingARequest() throws Exception {
        Path output = Files.createDirectory(directory.resolve("existing"));
        Path settings = Files.writeString(output.resolve("bullseye.properties"), "original settings\n");

        assertThrows(IOException.class, () -> EnrollmentBundle.install(output, invite("A", "0".repeat(64)), "",
                (invite, requestId, csr) -> {
                    throw new AssertionError("Enrollment reached the API for an occupied output path");
                }));
        assertEquals("original settings\n", Files.readString(settings));
        assertFalse(Files.exists(output.resolve("identity.p12")));
    }

    private static Invitation invite(String character, String fingerprint) {
        return new Invitation("edge-01", URI.create("https://uog.example.org/api/enrollment/v2/redeem"),
                "test bootstrap CA", Instant.parse("2030-01-01T00:00:00Z"), character.repeat(43), fingerprint);
    }
}
