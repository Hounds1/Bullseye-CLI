package io.bullseye.cli.enrollment;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

final class EnrollmentClient {
    private static final String REDEEM_PATH = "/api/enrollment/v2/redeem";
    private static final int MAX_INVITE_BYTES = 64 * 1_024;
    private static final int MAX_RESPONSE_BYTES = 128 * 1_024;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Pattern NODE_ID = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");
    private static final Pattern INVITE_CODE = Pattern.compile("[A-Za-z0-9_-]{43}");
    private static final Pattern KEY_SHA256 = Pattern.compile("[0-9a-fA-F]{64}");
    private static final Pattern PEM_CERTIFICATE = Pattern.compile(
            "-----BEGIN CERTIFICATE-----[\\r\\n]+([A-Za-z0-9+/=\\r\\n]+)-----END CERTIFICATE-----");
    private static final Set<String> SERVER_ERROR_CODES = Set.of(
            "INVALID_NODE_ID", "NODE_ID_IN_USE", "INVALID_OR_EXPIRED_CODE", "REQUEST_CONFLICT",
            "INVALID_CSR", "PUBLIC_KEY_MISMATCH", "INVALID_PUBLIC_KEY_SHA256",
            "TEMPORARY_UNAVAILABLE", "INVALID_REQUEST", "BODY_TOO_LARGE",
            "METHOD_NOT_ALLOWED", "NOT_FOUND", "UNAUTHORIZED");
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private EnrollmentClient() {
    }

    record Invitation(String nodeId, URI enrollmentUrl, String serverCaPem, Instant expiresAt,
                      String code, String publicKeySha256) {
    }

    record Registration(String nodeId, String certificateChainPem, String cccHost, int cccPort,
                        String cccServerCaPem) {
    }

    static Invitation readInvite(Path file) throws IOException {
        byte[] bytes;
        try (InputStream input = Files.newInputStream(file)) {
            bytes = input.readNBytes(MAX_INVITE_BYTES + 1);
        }
        if (bytes.length > MAX_INVITE_BYTES) {
            throw new IOException("Enrollment invitation is too large");
        }

        JsonNode invite = readVersionedJson(bytes, "invitation");
        String nodeId = requiredText(invite, "nodeId");
        if (!validNodeId(nodeId)) {
            throw new IOException("Invalid invitation nodeId");
        }

        URI enrollmentUrl = enrollmentUrl(requiredText(invite, "enrollmentUrl"));
        String code = requiredText(invite, "code");
        if (!INVITE_CODE.matcher(code).matches()) {
            throw new IOException("Invalid enrollment invitation code");
        }
        String publicKeySha256 = requiredText(invite, "publicKeySha256");
        if (!KEY_SHA256.matcher(publicKeySha256).matches()) {
            throw new IOException("Invalid enrollment invitation public key SHA-256");
        }

        Instant expiresAt;
        try {
            expiresAt = Instant.parse(requiredText(invite, "expiresAt"));
        } catch (DateTimeParseException exception) {
            throw new IOException("Invalid invitation expiresAt");
        }

        String serverCaPem = requiredText(invite, "serverCaPem");
        certificates(serverCaPem);
        return new Invitation(nodeId, enrollmentUrl, serverCaPem, expiresAt, code,
                publicKeySha256.toLowerCase(Locale.ROOT));
    }

    static boolean validNodeId(String nodeId) {
        return NODE_ID.matcher(nodeId).matches();
    }

    static Registration redeem(Invitation invite, UUID requestId, String csrPem)
            throws IOException, InterruptedException {
        byte[] body = JSON.writeValueAsBytes(JSON.createObjectNode()
                .put("requestId", requestId.toString())
                .put("csrPem", csrPem));
        HttpRequest request = HttpRequest.newBuilder(enrollmentUrl(invite.enrollmentUrl().toString()))
                .timeout(REQUEST_TIMEOUT)
                .header("Authorization", "Bearer " + invite.code())
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();

        SSLParameters tlsParameters = new SSLParameters();
        tlsParameters.setEndpointIdentificationAlgorithm("HTTPS");
        HttpClient http = HttpClient.newBuilder()
                .sslContext(trustContext(invite.serverCaPem()))
                .sslParameters(tlsParameters)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        HttpResponse<byte[]> response;
        try {
            response = send(http, request);
        } finally {
            http.shutdownNow();
        }
        if (response.statusCode() != 200) {
            throw responseError(response);
        }

        JsonNode result = readVersionedJson(response.body(), "response");
        String nodeId = requiredText(result, "nodeId");
        if (!invite.nodeId().equals(nodeId)) {
            throw new IOException("Enrollment response nodeId does not match the invitation");
        }

        JsonNode ccc = result.path("ccc");
        if (!ccc.isObject()) {
            throw new IOException("Invalid enrollment ccc field");
        }
        String cccHost = requiredText(ccc, "host");
        validateCccHost(cccHost);
        JsonNode port = ccc.path("port");
        if (!port.isIntegralNumber() || !port.canConvertToInt() || !validPort(port.intValue())) {
            throw new IOException("Invalid enrollment CCC port");
        }

        String chainPem = requiredText(result, "certificateChainPem");
        String cccServerCaPem = requiredText(ccc, "serverCaPem");
        certificates(chainPem);
        certificates(cccServerCaPem);
        return new Registration(nodeId, chainPem, cccHost, port.intValue(), cccServerCaPem);
    }

    static List<X509Certificate> certificates(String pem) throws IOException {
        List<X509Certificate> certificates = new ArrayList<>();
        String remaining = pem.strip();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            while (!remaining.isEmpty()) {
                var block = PEM_CERTIFICATE.matcher(remaining);
                if (!block.lookingAt()) {
                    throw new IOException("Invalid enrollment PEM certificate data");
                }
                String base64 = block.group(1).replace("\r", "").replace("\n", "");
                var der = new ByteArrayInputStream(Base64.getDecoder().decode(base64));
                var certificate = (X509Certificate) factory.generateCertificate(der);
                if (der.available() != 0) {
                    throw new IOException("Invalid enrollment PEM certificate data");
                }
                certificates.add(certificate);
                remaining = remaining.substring(block.end()).stripLeading();
            }
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw new IOException("Invalid enrollment PEM certificate data");
        }
        if (certificates.isEmpty()) {
            throw new IOException("Missing enrollment PEM certificate");
        }
        return List.copyOf(certificates);
    }

    private static SSLContext trustContext(String pem) throws IOException {
        List<X509Certificate> anchors = certificates(pem);
        try {
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            trust.load(null, null);
            for (int index = 0; index < anchors.size(); index++) {
                trust.setCertificateEntry("enrollment-ca-" + index, anchors.get(index));
            }
            TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            managers.init(trust);
            SSLContext tls = SSLContext.getInstance("TLS");
            tls.init(null, managers.getTrustManagers(), null);
            return tls;
        } catch (GeneralSecurityException exception) {
            throw new IOException("Unable to initialize enrollment HTTPS trust");
        }
    }

    private static HttpResponse<byte[]> send(HttpClient http, HttpRequest request)
            throws IOException, InterruptedException {
        var exchange = http.sendAsync(request, ignored -> new BoundedResponse());
        try {
            return exchange.get(REQUEST_TIMEOUT.toSeconds(), TimeUnit.SECONDS);
        } catch (TimeoutException exception) {
            exchange.cancel(true);
            throw new IOException("Enrollment HTTPS request timed out");
        } catch (InterruptedException exception) {
            exchange.cancel(true);
            throw exception;
        } catch (ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof OversizedResponse) {
                throw new IOException("Enrollment response is too large");
            }
            if (cause instanceof HttpTimeoutException) {
                throw new IOException("Enrollment HTTPS request timed out");
            }
            if (cause instanceof SSLHandshakeException) {
                throw new IOException("Enrollment HTTPS handshake failed");
            }
            throw new IOException("Enrollment HTTPS request failed");
        }
    }

    private static IOException responseError(HttpResponse<byte[]> response) {
        try {
            JsonNode code = readJson(response.body()).path("code");
            if (code.isTextual() && SERVER_ERROR_CODES.contains(code.textValue())) {
                return new IOException("Enrollment rejected: " + code.textValue());
            }
        } catch (IOException ignored) {
            // Report only status when the peer does not return a recognized error.
        }
        return new IOException("Enrollment failed with HTTP " + response.statusCode());
    }

    private static JsonNode readVersionedJson(byte[] bytes, String source) throws IOException {
        JsonNode json;
        try {
            json = readJson(bytes);
        } catch (IOException exception) {
            throw new IOException("Invalid enrollment " + source + " JSON");
        }
        JsonNode version = json.path("apiVersion");
        if (!version.isIntegralNumber()) {
            throw new IOException("Invalid enrollment " + source + " apiVersion");
        }
        if (!version.canConvertToInt() || version.intValue() != 2) {
            throw new IOException("Unsupported enrollment " + source + " apiVersion. Expected 2");
        }
        return json;
    }

    private static JsonNode readJson(byte[] bytes) throws IOException {
        String decoded = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString();
        JsonNode json = JSON.readTree(decoded);
        if (json == null || !json.isObject()) {
            throw new IOException("Enrollment JSON must be an object");
        }
        return json;
    }

    private static String requiredText(JsonNode object, String field) throws IOException {
        JsonNode value = object.path(field);
        if (!value.isTextual() || value.textValue().isBlank()) {
            throw new IOException("Invalid enrollment " + field + " field");
        }
        return value.textValue();
    }

    private static URI enrollmentUrl(String raw) throws IOException {
        try {
            URI uri = URI.create(raw);
            if ("https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null
                    && !uri.getRawAuthority().endsWith(":") && !uri.getHost().contains("%")
                    && uri.getRawUserInfo() == null && uri.getRawQuery() == null && uri.getRawFragment() == null
                    && REDEEM_PATH.equals(uri.getRawPath()) && (uri.getPort() == -1 || validPort(uri.getPort()))) {
                return uri;
            }
        } catch (IllegalArgumentException ignored) {
            // The original URL is intentionally absent from error messages.
        }
        throw new IOException("Enrollment URL must be an HTTPS v2 redemption URL");
    }

    private static void validateCccHost(String host) throws IOException {
        if (host.length() <= 254 && !host.contains("%")) {
            String authority = host.contains(":") && !host.startsWith("[") ? "[" + host + "]" : host;
            try {
                URI uri = URI.create("https://" + authority);
                if (authority.equals(uri.getHost())) {
                    return;
                }
            } catch (IllegalArgumentException ignored) {
                // Only plain DNS names and IPv4 or IPv6 addresses are accepted.
            }
        }
        throw new IOException("Invalid enrollment CCC host");
    }

    private static boolean validPort(int port) {
        return port >= 1 && port <= 65_535;
    }

    private static final class BoundedResponse implements HttpResponse.BodySubscriber<byte[]> {
        private final HttpResponse.BodySubscriber<byte[]> delegate = HttpResponse.BodySubscribers.ofByteArray();
        private int remaining = MAX_RESPONSE_BYTES;
        private Flow.Subscription subscription;

        @Override
        public CompletionStage<byte[]> getBody() {
            return delegate.getBody();
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            delegate.onSubscribe(subscription);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                remaining -= buffer.remaining();
                if (remaining < 0) {
                    delegate.onError(new OversizedResponse());
                    subscription.cancel();
                    return;
                }
            }
            delegate.onNext(buffers);
        }

        @Override
        public void onError(Throwable error) {
            delegate.onError(error);
        }

        @Override
        public void onComplete() {
            delegate.onComplete();
        }
    }

    private static final class OversizedResponse extends IOException {
    }
}
