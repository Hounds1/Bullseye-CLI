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

Prepare the enrollment key on the Core host.

```sh
./build/install/bullseye-cli/bin/bullseye enroll prepare \
  --node-id edge-01 --output bullseye-enrollment
```

Give the printed node ID and public key SHA-256 fingerprint to the UOG
operator through a trusted channel. The operator issues an invitation for
that exact pair. Transfer the invitation to the Core host over a trusted
channel and redeem it using the same output directory.

```sh
./build/install/bullseye-cli/bin/bullseye enroll \
  --invite edge-01.invite --output bullseye-enrollment \
  --core-config /etc/bullseye/bullseye.properties
```

The output directory defaults to `bullseye-enrollment`. The optional
`--core-config` file supplies existing Core settings, including the local
diagnostic and TCC options. The command creates a bundle with the merged
`bullseye.properties`, PKCS#12 identity and trust stores, and a JVM argument
file named `tls.jvm`.

Run the Core launcher with the generated properties and JVM arguments.

```sh
BULLSEYE_CORE_OPTS="\"@$PWD/bullseye-enrollment/tls.jvm\"" \
  /opt/bullseye-core/bin/bullseye-core "$PWD/bullseye-enrollment/bullseye.properties"
```

Core logs `Cluster connection authorized.` after CCC accepts the connection.
Enrollment uses the [UOG enrollment API v2][enrollment-v2]. Previously issued
v1 invitations need to be reissued for a prepared key. Already installed Core
identities continue to connect using their existing configuration.

If enrollment is interrupted, rerun the same command with the same invitation
and output. The local resume directory preserves the original key and request
for retry. A completed bundle for the same invitation is reused, including its
identity. Choose a fresh output directory for a different invitation.

[enrollment-v2]: https://github.com/Hounds1/Bullseye-UOG/blob/main/bullseye-ccc/ENROLLMENT-V2.md
