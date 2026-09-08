# VasDolly-go

English | [简体中文](README_zh-CN.md)

A pure-Go library and command-line tool for reading and writing VasDolly channel metadata in Android APK files. It changes only the channel metadata and does not re-sign the APK. The base APK remains untouched, and each channel is written to an independent output file.

Features:

- V1: appends `channel UTF-8 bytes + uint16LE(length) + ltlovezh` to the ZIP EOCD comment.
- V2/V3: writes the VasDolly pair `0x881155ff` (or Walle / custom Signing Block ID) into the APK Signing Block while preserving all other pairs and existing signature payloads.
- Library functions: `Pack`, `ReadChannel`, `ReadChannelWithBlockID`, `RemoveChannel`, and concurrent, atomic batch output through `PackFiles`.
- CLI commands: `vasdolly put|get|remove`.

## Library

```go
var output bytes.Buffer
// Default VasDolly ID (0x881155ff)
err := vasdolly.Pack(input, inputSize, "huawei", &output,
    vasdolly.TransformOptions{Mode: vasdolly.ModeAuto})

// Write Walle-compatible JSON payload or a custom Signing Block ID
err = vasdolly.Pack(input, inputSize, "huawei", &output,
    vasdolly.TransformOptions{Mode: vasdolly.ModeV2, BlockID: vasdolly.WallePairID})

// Read channel with a specific Signing Block ID (0 auto-detects VasDolly -> Walle -> V1)
channel, err := vasdolly.ReadChannelWithBlockID(input, inputSize, vasdolly.WallePairID)
```

`ModeAuto` prefers a V3/V2 APK Signing Block and falls back to V1. Set `VerifyInput: true` to verify the selected signing scheme before writing; structural validation is always performed. V1 mode rejects APKs that also contain V2/V3 signatures to avoid invalidating the stronger signature.

## CLI

```text
vasdolly put -c "huawei,xiaomi" app.apk dist/
vasdolly put -c channels.txt --mode v1 app.apk dist/

# Use Walle-compatible JSON channel metadata
vasdolly put -c channels.txt --mode v2 --block-id Walle app.apk dist/
vasdolly get -c huawei-app.apk
vasdolly get -c huawei-app.apk --block-id Walle
vasdolly get -s huawei-app.apk
vasdolly remove -c huawei-app.apk cleaned.apk
vasdolly remove -c huawei-app.apk --block-id Walle cleaned.apk
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
|-- cmd/vasdolly/   # Command-line entry point
|-- internal/core/  # APK parsing, signature detection, and channel transforms
|-- docs/           # Design, research, and maintenance documentation
`-- vasdolly.go     # Stable public Go interface
```

The root package preserves the `github.com/CodeIdeal/VasDolly-go` import path. Implementation that external projects must not import directly lives in `internal/core`. There is no separate second public package, so the repository does not need a `pkg/` directory.

The runtime depends on `github.com/agusibrahim/apksig-go v1.1.0`. It does not invoke Java, Android SDK tools, `apksigner`, or CGO.
