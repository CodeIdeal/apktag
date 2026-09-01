# Research: Go dependency boundary and attribution

## Question

What dependency and API boundary gives the project a pure-Go runtime while using `apksig-go` safely, without adding the reference projects to the runtime dependency graph? License and attribution decisions are explicitly deferred from this effort.

## Findings

1. `github.com/agusibrahim/apksig-go` publishes a Go module at tag `v1.1.0`. Its `go.mod` declares Go 1.23 and lists `github.com/pavlo-v-chernykh/keystore-go/v4`, `golang.org/x/crypto`, and `software.sslmate.com/src/go-pkcs12` as indirect dependencies. The module cache resolves `v1.1.0` to commit `a0389a9d7f83032504713ac6052f85edfb52f64b`.
   - Sources: [apksig-go go.mod](https://github.com/agusibrahim/apksig-go/blob/v1.1.0/go.mod), [v1.1.0 tag](https://github.com/agusibrahim/apksig-go/releases/tag/v1.1.0), [Go module proxy metadata](https://proxy.golang.org/github.com/agusibrahim/apksig-go/@v/v1.1.0.info)

2. The API needed for channel injection is exported and stays within three narrow packages: `pkg/datasource` supplies `DataSource`, `NewReaderAt`, `NewBytes`, and `ReadAll`; `pkg/zip` supplies `FindEOCD` and byte-exact ZIP/CD structures; `pkg/apksigblock` supplies `Find`, parsed `Pair` values, and well-known IDs. `pkg/apkverifier` exposes `Verify` for optional input/output validation. These APIs allow an adapter in this repository without importing the upstream command binaries.
   - Sources: [`datasource.go`](https://github.com/agusibrahim/apksig-go/blob/v1.1.0/pkg/datasource/datasource.go), [`zip.go`](https://github.com/agusibrahim/apksig-go/blob/v1.1.0/pkg/zip/zip.go), [`block.go`](https://github.com/agusibrahim/apksig-go/blob/v1.1.0/pkg/apksigblock/block.go), [`apkverifier.go`](https://github.com/agusibrahim/apksig-go/blob/v1.1.0/pkg/apkverifier/apkverifier.go)

3. `github.com/avast/apkverifier` and `github.com/avast/apkparser` are useful reference implementations for verification and Android binary XML parsing, but neither is required to implement the channel metadata rewrite when `apksig-go` supplies the ZIP/signing-block primitives. They remain outside the runtime dependency graph for this effort.
   - Sources: [apkverifier go.mod](https://github.com/avast/apkverifier/blob/master/go.mod), [apkparser go.mod](https://github.com/avast/apkparser/blob/master/go.mod)

5. The external package `signer.AssembleSigningBlock` is useful as a format reference but is not sufficient as the sole writer seam: its implementation always appends a padding pair and uses the `0x42726577` ID, which is also exposed as the V4/signing-block ID. The channel writer therefore needs a local, narrowly scoped assembler that preserves the parsed pair sequence and distinguishes existing pairs from newly generated padding according to the Signing Block research decision. This is still a pure-Go adapter over the upstream `DataSource`, EOCD, and parsed-pair APIs rather than a fork of the dependency.
   - Source: [`signer.go` AssembleSigningBlock](https://github.com/agusibrahim/apksig-go/blob/v1.1.0/pkg/signer/signer.go#L158-L216)

## Decision

Declare a direct dependency on `github.com/agusibrahim/apksig-go v1.1.0`. Import only its `datasource`, `zip`, `apksigblock`, and optional `apkverifier` packages through a local adapter. Do not depend on `apkverifier` or `apkparser`; use their source and test fixtures only as research references. License and attribution handling is deferred and is not an acceptance criterion for this implementation.

## Implementation contract

- Runtime must compile and operate with Go and module dependencies only.
- No shelling out to Java, `apksigner`, Android SDK tools, or external verifier binaries.
- Keep the dependency behind one internal adapter seam so an upstream API change affects one boundary.
- Pin the direct dependency to a reviewed release and run `go mod verify` in CI.
- Re-check the exported API when upgrading the module.
