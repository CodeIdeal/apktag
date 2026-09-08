# Support Walle and custom Signing Block IDs for channel metadata

Extend [ADR-0002](0002-preserve-signatures-when-injecting-channel-metadata.md) to support Walle channel metadata and arbitrary 32-bit Signing Block IDs. While the packaging pipeline continues to preserve APK signatures without re-signing, the Signing Block injection and extraction mechanism now supports:

1. **Walle channel pair ID (`0x71777777`)**: encodes channel metadata as a JSON object `{"channel": "<name>"}` per Meituan Walle specifications, writing a canonical JSON object and tolerating extra fields when reading existing channel packages.
2. **Custom Signing Block IDs**: allows callers to inject and read raw UTF-8 channel strings under any valid 32-bit unsigned ID.
3. **Detection and Fallback**: `ReadChannel` checks the default VasDolly pair (`0x881155ff`), then Walle (`0x71777777`), and falls back to V1 ZIP comments. `ReadChannelWithBlockID` and CLI `--block-id` allow explicit pair targeting.

## Considered Options

- Restrict packaging exclusively to VasDolly's `0x881155ff` ID and require external tools or migration steps for Walle packages.
- Provide a separate CLI tool or package for Walle channel operations.
- Integrate Walle payload validation/formatting and configurable `BlockID` directly into `TransformOptions`, `ReadChannelWithBlockID`, and `vasdolly put|get|remove`.

## Consequences

- VasDolly remains the default behavior (`BlockID == 0` defaults to `0x881155ff`).
- Projects using Walle or proprietary Signing Block IDs can use VasDolly-go directly for channel packaging, inspection, and removal without breaking existing signatures.
- Writing or reading Walle metadata validates JSON formatting and ensures non-empty channel values.
