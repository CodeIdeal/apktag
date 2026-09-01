# Use a pure-Go runtime with apksig-go as the signing foundation

The channel packer uses Go code at runtime and does not invoke Java, Android SDK tools, `apksigner`, or CGO. It consumes the Apache-2.0 `apksig-go` module for APK ZIP/signing-block primitives; the LGPL reference projects remain format and compatibility references rather than runtime dependencies.

## Considered Options

- Invoke the Android SDK's `apksigner` for parsing or rewriting.
- Vendor all APK signing code and avoid third-party modules.
- Use `apksig-go` as the narrow Go-native foundation.

## Consequences

The project remains usable in environments without an Android SDK, while upgrades to the `apksig-go` API and its Apache-2.0 dependency remain part of maintenance.
