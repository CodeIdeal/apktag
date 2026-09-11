# Keep the public facade and internalize the implementation

The module exposes `github.com/CodeIdeal/apktag` as its public package and moves APK parsing, signing-scheme detection, channel transformation, and batch output implementation into `internal/core`. The root package is a facade that preserves the existing functions, types, constants, and sentinel errors.

## Considered Options

- Keep all implementation files in the repository root.
- Move the public package under `pkg/vasdolly` and change the import path.
- Keep the public package at the root and place private implementation in `internal/core`.

## Consequences

Internalizing the implementation does not change caller imports. Go prevents external modules from importing implementation details, while maintainers get one local module for APK invariants. The root facade adds a small delegation layer, and its public behavior must remain covered independently from implementation-level tests.

The 2026-09-11 project rename supersedes the original decision to retain the `github.com/CodeIdeal/VasDolly-go` import path: callers must now use `github.com/CodeIdeal/apktag` and package `apktag`. The CLI is `apktag`; VasDolly and Walle remain format names. This gives the library and CLI one name covering both supported formats, at the cost of a one-time import migration.
