package io.bullseye.cli.enrollment;

import java.io.IOException;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Properties;

public final class EnrollCommand {
    private static final String USAGE =
            "Usage: bullseye enroll --invite <file> [--output <directory>] [--core-config <file>]";

    private EnrollCommand() {}

    public static int run(String[] arguments, PrintStream out, PrintStream err) {
        if (arguments.length == 1 && ("--help".equals(arguments[0]) || "-h".equals(arguments[0]))) {
            out.println(USAGE);
            out.println("Default output directory: bullseye-enrollment");
            return 0;
        }

        var options = parseOptions(arguments);
        if (options == null) {
            err.println(USAGE);
            return 2;
        }

        try {
            var invite = EnrollmentClient.readInvite(Path.of(options.get("--invite")));
            Path output = Path.of(options.getOrDefault("--output", "bullseye-enrollment"))
                    .toAbsolutePath().normalize();
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

    private static HashMap<String, String> parseOptions(String[] arguments) {
        if (arguments.length % 2 != 0) {
            return null;
        }
        var options = new HashMap<String, String>();
        for (int index = 0; index < arguments.length; index += 2) {
            String option = arguments[index];
            if (!"--invite".equals(option) && !"--output".equals(option) && !"--core-config".equals(option)) {
                return null;
            }
            String value = arguments[index + 1];
            if (value.isBlank() || value.startsWith("--") || options.putIfAbsent(option, value) != null) {
                return null;
            }
        }
        return options.containsKey("--invite") ? options : null;
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
