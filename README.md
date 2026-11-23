# Bullseye CLI

Bullseye CLI is the command-line tool for configuring Bullseye Core and
operating Bullseye UOG. It is built and released from this repository.

## Build and run

Use JDK 25 and the included Gradle wrapper.

```sh
./gradlew installDist distZip
./build/install/bullseye-cli/bin/bullseye --help
./build/install/bullseye-cli/bin/bullseye --version
```

On Windows, use `gradlew.bat` and `build\install\bullseye-cli\bin\bullseye.bat`.
The distribution ZIP is under `build/distributions`.

## Core node enrollment

Core node enrollment is planned around UOG's versioned enrollment API.
The CLI will use an invitation issued by UOG and install the resulting
credentials and connection settings on the Core host.
