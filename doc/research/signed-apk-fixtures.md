# Research: signed APK fixtures and verification strategy

## Scope

本研究为纯 Go 多渠道打包实现定义可复现的签名 APK fixture、签名方案组合和验证边界。重点是确认 V1、V2、V3 渠道注入的顺序，哪些签名在变更后仍然有效，以及测试在没有 Android SDK 工具时如何运行。研究只使用上游源码和固定提交；`apkverifier` 与 `apkparser` 作为参考，不作为运行时依赖。

## Primary sources

研究基于以下固定源码版本（2026-09-01 检索）：

| Source | Revision | Relevant material |
| --- | --- | --- |
| [Tencent/VasDolly](https://github.com/Tencent/VasDolly/tree/066426280ad8c391bc86eb823b2b8e5f49d80bec) | `066426280ad8c391bc86eb823b2b8e5f49d80bec` | V1/V2/V3 channel constants, signing-block rewrite, fixture expectations |
| [agusibrahim/apksig-go](https://github.com/agusibrahim/apksig-go/tree/a0389a9d7f83032504713ac6052f85edfb52f64b) | `a0389a9d7f83032504713ac6052f85edfb52f64b` | Pure-Go V1 signer, V2/V3 writer, signing-block parser and verifier |
| [avast/apkverifier](https://github.com/avast/apkverifier/tree/d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071) | `d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071` | Scheme selection and scheme-specific verification results |
| [avast/apkparser](https://github.com/avast/apkparser/tree/7fcaee440f681166528e5a582eb628602360b3ef) | `7fcaee440f681166528e5a582eb628602360b3ef` | ZIP entry and APK structure parsing used by the verifier |
| [AOSP platform/tools/apksig](https://android.googlesource.com/platform/tools/apksig/+/184702d9d18877edf9e5296c4e191cf0aa2b5fbb) | `184702d9d18877edf9e5296c4e191cf0aa2b5fbb` | Official signing-block and content-digest behavior |

The local environment has Go `go1.26.5 darwin/arm64`. `go test ./...` passes in each of the three reference Go repositories. `apksigner` and `zipalign` are not on `PATH`, but Android SDK build-tools are installed under `/Users/kaka/SDK/AndroidSDK/build-tools/`; `/Users/kaka/SDK/AndroidSDK/build-tools/37.0.0/apksigner` reports version `0.9`. An AOSP fixture named `v1v2v3-with-rsa-2048-lineage-3-signers.apk` passes V1/V2/V3 verification with both that SDK `apksigner` and `apksig-go`.

## Findings

### 1. Pure-Go signing has a required V1/V2/V3 order

`apksig-go/pkg/v1signer.Sign` generates the V1 `META-INF/MANIFEST.MF`, `.SF`, and `.RSA` or `.EC` entries, but it does not inject those entries into a ZIP. `apksig-go/pkg/apkwriter.SignedAPKWriter` writes V2 by default and can write V3 when configured, but does not write V1 entries. Sources: [`v1signer.Sign`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/v1signer/v1signer.go), [`SignedAPKWriter`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apkwriter/apkwriter.go).

Consequently, a pure-Go V1+V2/V3 fixture must be assembled in this order:

1. Build the unsigned ZIP/APK entries.
2. Generate V1 signature entries and inject them into the ZIP.
3. Run the V2/V3 signer over that resulting ZIP.

Signing V2/V3 first and then injecting V1 entries changes the ZIP entry set after the stronger signature was calculated and invalidates the result. V1-only fixtures can stop after step 2. V3-only output needs custom assembly with `signer.SignerPayloadV3`, `signer.Pair`, and `signer.AssembleSigningBlock`, or a known-good AOSP V3-only fixture; the default writer configuration is not enough to establish V3-only coverage.

### 2. Fixture matrix must separate scheme presence from aggregate validity

`apkverifier.Verify` checks V3.1, then V3, then V2, and finally V1. Its aggregate result is not sufficient for acceptance tests: a fallback to V1 can make an APK appear usable even when the intended V2/V3 scheme is invalid. Tests must assert the scheme-specific fields `V1Verified`, `V2Verified`, and `V3Verified`, together with the selected SDK range and signer/certificate result where relevant. Source: [`apkverifier.Verify`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apkverifier/apkverifier.go).

The minimum positive fixture set is therefore:

| Fixture | Construction | Required assertions |
| --- | --- | --- |
| V1-only | Unsigned ZIP plus injected V1 entries | `V1Verified`; no V2/V3 fallback is counted |
| V2-only | `SignedAPKWriter` with V2 | `V2Verified`; channel pair survives read/remove |
| V3-only | Custom V3 signing-block assembly or AOSP fixture | `V3Verified` and the expected SDK range |
| V1+V2 | V1 injection followed by V2 signing | `V1Verified` and `V2Verified` |
| V1+V2+V3 | V1 injection followed by V2/V3 signing | `V1Verified`, `V2Verified`, and `V3Verified` |
| V2+V3 | Writer configured with a V3 SDK range | `V2Verified` and `V3Verified` |

Fixtures should use deterministic test keys and stable entry bytes. They should be checked into the repository only if licensing and size allow; otherwise the test harness should generate the unsigned ZIP and signatures deterministically from test material. Generated fixtures must never depend on a developer's private signing key.

### 3. V2/V3 metadata insertion can preserve existing signatures

The V2/V3 content digest does not cover the Signing Block as one opaque byte range. AOSP defines the protected content as the bytes before the Signing Block, the Central Directory, and the EOCD with the Central Directory offset patched to the Signing Block start ([AOSP V2 integrity-protected contents](https://source.android.com/docs/security/features/apksigning/v2#integrity-protected-contents)). Therefore, adding or replacing a channel metadata pair can preserve an existing V2/V3 signature if the block is rebuilt with valid sizes and the Central Directory/EOCD offsets are adjusted correctly.

VasDolly uses metadata ID `0x881155ff`. Its V3 signature ID is `0xf05368c0`, and its V1 marker is `ltlovezh`. The writer preserves ordered ID/value pairs, removes and recomputes the padding pair `0x42726577`, and aligns the rebuilt Signing Block to 4096 bytes. These details are structural acceptance criteria, not merely implementation preferences. Source: [VasDolly channel constants](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/ChannelConstants.java), [VasDolly V2/V3 writer](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/writer/src/main/java/com/tencent/vasdolly/writer/V2SchemeUtil.java).

`apksig-go/pkg/apksigblock.Find` validates the Signing Block magic, header/footer size equality, and pair-length bounds. The Go implementation should use equivalent checks before reading or rewriting any pair. Source: [`apksigblock.Find`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apksigblock/block.go).

Unknown pairs, source-stamp data, lineage bytes, and any future IDs must be preserved byte-for-byte and in their original order unless the requested operation explicitly targets the VasDolly metadata pair. V4 `.idsig` is a separate sidecar and is not regenerated by this implementation; any APK mutation requires the caller to regenerate it.

### 4. V1 comment mutation is safe only for V1-only APKs

VasDolly stores the V1 channel in the ZIP EOCD comment as channel UTF-8 bytes, a little-endian `uint16` byte length, and the marker `ltlovezh`. The V1 comment is not part of the signed JAR entries, so appending/replacing only the EOCD comment preserves V1/JAR verification. This is consistent with the V1 writer's documented no-second-signing behavior. Sources: [VasDolly V1 channel writer](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V1SchemeUtil.java), [VasDolly channel writer API](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/writer/src/main/java/com/tencent/vasdolly/writer/ChannelWriter.java), [AOSP V1 overview](https://source.android.com/docs/security/features/apksigning#v1).

The same operation is not safe for an APK that has V2 or V3: AOSP protects the EOCD and the Central Directory in the stronger schemes. A V1 comment mutation therefore invalidates V2/V3 verification even though V1 may remain valid. Auto-detection must prefer V3/V2 and must not silently select V1 for a mixed-scheme APK. Tests should include a negative case proving that V1 mutation is rejected in the default mode when stronger schemes are present.

### 5. Interoperability with `apksigner` is optional

The runtime must remain pure Go and must not shell out to Android tools. An optional integration test may locate `apksigner` with `exec.LookPath` or an explicitly configured SDK path, run it against generated fixtures, and compare its scheme-specific pass/fail result with `apksig-go`. The test must skip cleanly when the tool is unavailable and must never make an SDK installation a build or runtime dependency.

The local SDK result above establishes one useful baseline: the AOSP V1+V2+V3 fixture with three RSA-2048 lineage signers is accepted by both implementations. It does not replace tests of generated outputs, malformed structures, or all supported algorithm combinations.

## Acceptance matrix

### Positive cases

- V1-only: construct a pure-Go ZIP, inject V1 signature entries, append/read/remove the V1 channel comment, and assert `V1Verified` before and after channel operations.
- V2-only: construct with `SignedAPKWriter`, inject/read/remove the `0x881155ff` pair, and assert `V2Verified` after each valid rewrite.
- V3-only: use a custom V3 block assembler or a pinned AOSP fixture and assert `V3Verified` with the expected SDK range.
- V1+V2 and V1+V2+V3: inject V1 entries first, sign V2/V3 second, and assert every intended scheme-specific verification field.
- V2+V3: configure the writer for a V3 SDK range and assert both V2 and V3 verification.
- Pair preservation: retain unknown pairs, source-stamp/lineage data, pair ordering, valid padding, and 4096-byte Signing Block alignment.
- V1 preservation: retain the original EOCD comment prefix exactly and restore it exactly after removing a valid V1 suffix.

### Negative and malformed cases

- Reject invalid EOCD/comment lengths, ZIP64 inputs outside the V1 path, malformed Central Directory data, and truncated APKs.
- Reject bad Signing Block magic or size equality, pair-length overflow/truncation, duplicate/ambiguous target pairs, and invalid block alignment where the format requires it.
- Reject corrupt V1/V2/V3 signature, signed-data, digest, certificate, public-key, or signer records; unsupported algorithms; missing certificates; and a broken second signer.
- Reject V1 comment mutation in auto mode when a valid V2/V3 signature is present; never claim aggregate verification is enough.
- Verify that any failed write leaves the source and destination bytes unchanged and that V4 `.idsig` regeneration remains caller-managed.

### Optional tool interoperability

- If `apksigner` is available, verify every generated positive fixture and compare its scheme results with the Go verifier.
- If `apksigner` is unavailable, skip only the external-tool test; all pure-Go construction, parsing, mutation, and verification tests remain mandatory.

## Implementation decision

Use pure-Go fixture construction and `apksig-go` verification as the required test path. Add a narrow optional `apksigner` interoperability path for environments with Android SDK build-tools. Build V1 signatures before V2/V3 signatures, treat V1 comment writes as V1-only operations, preserve all non-target Signing Block pairs, and assert scheme-specific verification fields in every fixture test. Do not add `apkverifier` or `apkparser` as runtime dependencies, and do not attempt V4 sidecar generation in the first implementation.
