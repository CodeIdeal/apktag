# Keep the public facade and internalize the implementation

The module keeps `github.com/CodeIdeal/VasDolly-go` as its public package and moves APK parsing, signing-scheme detection, channel transformation, and batch output implementation into `internal/core`. The root package is a facade that preserves the existing functions, types, constants, and sentinel errors.

## Considered Options

- Keep all implementation files in the repository root.
- Move the public package under `pkg/vasdolly` and change the import path.
- Keep the public package at the root and place private implementation in `internal/core`.

## Consequences

External callers continue to compile without changing imports. Go prevents external modules from importing implementation details, while maintainers get one local module for APK invariants. The root facade adds a small delegation layer, and its public behavior must remain covered independently from implementation-level tests.
