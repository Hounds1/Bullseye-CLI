package io.bullseye.cli.enrollment;

import java.io.IOException;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

public final class EnrollCommand {
    private static final String USAGE =
            "Usage: bullseye enroll --invite <file> [--output <directory>] [--core-config <file>]";
    private static final String PREPARE_USAGE =
            "Usage: bullseye enroll prepare --node-id <id> [--output <directory>]";

    private EnrollCommand() {}

    public static int run(String[] arguments, PrintStream out, PrintStream err) {
        boolean prepare = arguments.length != 0 && "prepare".equals(arguments[0]);
        String[] optionsArgs = prepare ? Arrays.copyOfRange(arguments, 1, arguments.length) : arguments;
        String usage = prepare ? PREPARE_USAGE : USAGE;
        if (optionsArgs.length == 1 && ("--help".equals(optionsArgs[0]) || "-h".equals(optionsArgs[0]))) {
            if (!prepare) {
                out.println(PREPARE_USAGE);
            }
            out.println(usage);
            out.println("Default output directory: bullseye-enrollment");
            return 0;
        }

        var options = parseOptions(optionsArgs,
                prepare ? Set.of("--node-id", "--output") : Set.of("--invite", "--output", "--core-config"));
        if (options == null || !options.containsKey(prepare ? "--node-id" : "--invite")) {
            err.println(usage);
            return 2;
        }

        try {
            Path output = Path.of(options.getOrDefault("--output", "bullseye-enrollment"))
                    .toAbsolutePath().normalize();
            if (prepare) {
                String nodeId = options.get("--node-id");
                if (!EnrollmentClient.validNodeId(nodeId)) {
                    err.println("Invalid enrollment node ID.");
                    return 2;
                }
                String fingerprint = EnrollmentBundle.prepare(output, nodeId);
                out.println("Node ID: " + nodeId);
                out.println("Public key SHA-256: " + fingerprint);
                return 0;
            }

            var invite = EnrollmentClient.readInvite(Path.of(options.get("--invite")));
            String baseConfig = options.containsKey("--core-config")
                    ? loadCoreConfig(Path.of(options.get("--core-config"))) : "";
            EnrollmentBundle.install(output, invite, baseConfig, EnrollmentClient::redeem);
            out.println("Core enrollment ready. node=" + invite.nodeId());
            out.println("Core properties: " + output.resolve("bullseye.properties"));
            out.println("JVM options: " + output.resolve("tls.jvm"));
            return 0;
        } catch (InvalidPathException invalid) {
            err.println("Enrollment path is invalid.");
            return 2;
        } catch (IOException failure) {
            err.println("Enrollment failed. " + failure.getMessage());
            return 1;
        } catch (InterruptedException stopping) {
            Thread.currentThread().interrupt();
            err.println("Enrollment interrupted. Retry using the same invitation and output directory.");
            return 1;
        }
    }

    private static Map<String, String> parseOptions(String[] arguments, Set<String> allowed) {
        if (arguments.length % 2 != 0) {
            return null;
        }
        var options = new HashMap<String, String>();
        for (int index = 0; index < arguments.length; index += 2) {
            String option = arguments[index];
            if (!allowed.contains(option)) {
                return null;
            }
            String value = arguments[index + 1];
            if (value.isBlank() || value.startsWith("--") || options.putIfAbsent(option, value) != null) {
                return null;
            }
        }
        return options;
    }

    private static String loadCoreConfig(Path file) throws IOException {
        String contents = Files.readString(file);
        try {
            new Properties().load(new StringReader(contents));
        } catch (IllegalArgumentException invalid) {
            throw new IOException("Invalid base Core properties file.");
        }
        return contents;
    }
}
