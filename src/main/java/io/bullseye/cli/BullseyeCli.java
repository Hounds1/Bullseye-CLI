package io.bullseye.cli;

import io.bullseye.cli.enrollment.EnrollCommand;

import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class BullseyeCli {
    private static final String USAGE = "Usage: bullseye [--help | --version]";

    private BullseyeCli() {}

    public static void main(String[] arguments) {
        int exitCode = run(arguments, System.out, System.err);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    private static int run(String[] arguments, PrintStream out, PrintStream err) {
        if (arguments.length > 0 && "enroll".equals(arguments[0])) {
            return EnrollCommand.run(Arrays.copyOfRange(arguments, 1, arguments.length), out, err);
        }
        if (arguments.length == 0) {
            printHelp(out);
            return 0;
        }
        if (arguments.length == 1) {
            switch (arguments[0]) {
                case "-h", "--help" -> {
                    printHelp(out);
                    return 0;
                }
                case "--version" -> {
                    out.println("Bullseye CLI " + version());
                    return 0;
                }
                default -> { }
            }
        }
        err.println(USAGE);
        return 2;
    }

    private static void printHelp(PrintStream out) {
        out.println("Bullseye CLI");
        out.println(USAGE);
        out.println("       bullseye enroll prepare --node-id <id> [--output <directory>]");
        out.println("       bullseye enroll --invite <file> [--output <directory>] [--core-config <file>]");
    }

    private static String version() {
        try (var resource = BullseyeCli.class.getResourceAsStream("version.txt")) {
            if (resource == null) {
                throw new IllegalStateException("CLI version resource is missing");
            }
            return new String(resource.readAllBytes(), StandardCharsets.UTF_8).strip();
        } catch (IOException failure) {
            throw new UncheckedIOException("Unable to read the CLI version", failure);
        }
    }
}
