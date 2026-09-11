# apktag

English | [简体中文](README_zh-CN.md)

A pure-Go library and command-line tool for reading and writing channel metadata in Android APK files, compatible with VasDolly, Walle, and custom Signing Block IDs. It reads and writes only the channel metadata and does not re-sign the APK. The base APK remains untouched, and each channel is written to an independent output file.

Features:

- V1: appends `channel UTF-8 bytes + uint16LE(length) + ltlovezh` to the ZIP EOCD comment.
- V2/V3: writes the VasDolly pair `0x881155ff` (or Walle / custom Signing Block ID) into the APK Signing Block while preserving all other pairs and existing signature payloads.
- Library functions: `Pack`, `ReadChannel`, `ReadChannelWithBlockID`, `RemoveChannel`, and concurrent, atomic batch output through `PackFiles`.
- CLI commands: `apktag put|get|remove`.

## Library

Import `github.com/CodeIdeal/apktag` and use the `apktag` package.

```go
var output bytes.Buffer
// Default VasDolly ID (0x881155ff)
err := apktag.Pack(input, inputSize, "huawei", &output,
    apktag.TransformOptions{Mode: apktag.ModeAuto})

// Write Walle-compatible JSON payload or a custom Signing Block ID
err = apktag.Pack(input, inputSize, "huawei", &output,
    apktag.TransformOptions{Mode: apktag.ModeV2, BlockID: apktag.WallePairID})

// Read channel with a specific Signing Block ID (0 auto-detects VasDolly -> Walle -> V1)
channel, err := apktag.ReadChannelWithBlockID(input, inputSize, apktag.WallePairID)
```

`ModeAuto` prefers a V3/V2 APK Signing Block and falls back to V1. Set `VerifyInput: true` to verify the selected signing scheme before writing; structural validation is always performed. V1 mode rejects APKs that also contain V2/V3 signatures to avoid invalidating the stronger signature.

## CLI

Build the CLI from this checkout:

```sh
go build -o apktag ./cmd/apktag
./apktag --help
```

```text
apktag put -c "huawei,xiaomi" app.apk dist/
apktag put -c channels.txt --mode v1 app.apk dist/

# Use Walle-compatible JSON channel metadata
apktag put -c channels.txt --mode v2 --block-id Walle app.apk dist/
apktag get -c huawei-app.apk
apktag get -c huawei-app.apk --block-id Walle
apktag get -s huawei-app.apk
apktag remove -c huawei-app.apk cleaned.apk
apktag remove -c huawei-app.apk --block-id Walle cleaned.apk
```

`channels.txt` contains one channel per line. Empty lines and surrounding whitespace are ignored, and duplicate channels keep only their first occurrence.

For V2/V3 packaging, `--block-id` accepts `VasDolly` (the default, `0x881155FF`), `Walle` (`0x71777777`), or a custom 32-bit hexadecimal ID. Walle payloads are JSON objects containing a non-empty string `channel` field; extra fields are accepted when reading existing packages.

V4 `.idsig` files, AAB files, APK re-signing, and Source Stamp regeneration are outside the project scope. After modifying an APK with a V4 signature, the caller is responsible for regenerating its sidecar file.

## Development

```text
go test ./...
go vet ./...
```

The repository follows a focused version of the common Go project layout:

```text
.
|-- cmd/apktag/     # Command-line entry point
|-- internal/core/  # APK parsing, signature detection, and channel transforms
|-- docs/           # Design, research, and maintenance documentation
`-- apktag.go       # Stable public Go interface
```

The root package uses the `github.com/CodeIdeal/apktag` import path. Implementation that external projects must not import directly lives in `internal/core`. There is no separate second public package, so the repository does not need a `pkg/` directory.

The runtime depends on `github.com/agusibrahim/apksig-go v1.1.0`. It does not invoke Java, Android SDK tools, `apksigner`, or CGO.

## External interoperability tests

The opt-in black-box suite runs the published VasDolly and Walle JARs against the same generated APK fixtures. It covers cross-reading, removal, signature combinations, channel and ZIP comment boundaries, Signing Block boundaries, batch input forms, metadata coexistence, malformed APKs, and MD5/structure comparisons.

```sh
VASDOLLY_JAR=/path/to/VasDolly.jar \
WALLE_JAR=/path/to/walle.jar \
go test -tags=interop ./internal/core -run TestInterop -count=1 -v -timeout=20m
```

Set `APKSIGNER` to an `apksigner` executable for an additional independent signature check. Set `INTEROP_ARTIFACT_DIR` to retain files and command logs from failed cases. The reference JARs are test-only dependencies and are never downloaded or committed.
