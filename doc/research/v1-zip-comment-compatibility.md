# Research: VasDolly V1 ZIP comment compatibility

## Scope

本票据回答 VasDolly V1 ZIP comment 的兼容性问题：线格式、UTF-8 与字节长度、已有 comment、重复渠道、删除、溢出，以及对 JAR/V1 签名验证的影响。结论区分“VasDolly 3.0.6 的实际行为”和 Go 实现应采用的安全契约；上游的历史缺陷不应被当作兼容性要求复制。

## Primary sources

研究基于以下固定源码版本（2026-09-01 检索）：

| Source | Revision | Relevant material |
| --- | --- | --- |
| [Tencent/VasDolly](https://github.com/Tencent/VasDolly/tree/066426280ad8c391bc86eb823b2b8e5f49d80bec) | `066426280ad8c391bc86eb823b2b8e5f49d80bec` (`release 3.0.6`) | V1 writer/reader, constants, ZIP helpers |
| [agusibrahim/apksig-go](https://github.com/agusibrahim/apksig-go/tree/a0389a9d7f83032504713ac6052f85edfb52f64b) | `a0389a9d7f83032504713ac6052f85edfb52f64b` | EOCD parser and Go V1 verifier |
| [avast/apkverifier](https://github.com/avast/apkverifier/tree/d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071) | `d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071` | Android-compatible V1 verification and downgrade check |
| [avast/apkparser](https://github.com/avast/apkparser/tree/7fcaee440f681166528e5a582eb628602360b3ef) | `7fcaee440f681166528e5a582eb628602360b3ef` | ZIP reader used by `apkverifier` |

格式规范依据 [PKWARE APPNOTE.TXT §4.3.1, §4.3.3, §4.3.16, §4.4.1](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)。签名语义依据 [AOSP APK signing overview 的 JAR signing (v1) 部分](https://source.android.com/docs/security/features/apksigning#v1)、[AOSP v2 integrity-protected contents](https://source.android.com/docs/security/features/apksigning/v2#integrity-protected-contents) 和 [Oracle Signed JAR specification](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File)。

## Findings

### 1. V1 wire format is an appended byte suffix

VasDolly defines UTF-8 as `CONTENT_CHARSET` and the eight-byte V1 marker as ASCII `ltlovezh` ([`ChannelConstants.java`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/ChannelConstants.java#L23-L27)). `writeChannel` first converts the Java `String` with `getBytes("UTF-8")`, then appends the following bytes to the existing EOCD comment ([`V1SchemeUtil.writeChannel`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V1SchemeUtil.java#L51-L120)):

```text
existing ZIP comment
channel UTF-8 bytes
channel byte length: uint16 little-endian
ltlovezh
```

The ZIP comment itself is a byte sequence; APPNOTE specifies a two-byte `.ZIP file comment length` followed by a variable-size comment and does not assign it a character encoding ([APPNOTE §4.3.16](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)). VasDolly's UTF-8 choice is therefore an application-level convention, not a ZIP requirement. The ZIP fields are little-endian ([APPNOTE §4.3.3](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)).

The `channel` length stored inside the suffix is the encoded byte length, not the Java `String.length()` character count: the writer uses `comment.length` after UTF-8 encoding. This matters for non-ASCII channels such as `渠道`: the suffix length is the number of UTF-8 bytes.

### 2. EOCD and comment bounds

The regular EOCD is at least 22 bytes and has a two-byte unsigned comment-length field; the maximum representable comment is therefore `0xffff` (65535) bytes. VasDolly's AOSP-derived ZIP helper searches backwards from EOF and accepts a candidate only when its declared comment length reaches exactly to EOF; the search is bounded by 65535 bytes ([`ZipUtils.findZipEndOfCentralDirectoryRecord`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/apk/ZipUtils.java#L53-L81), [`find...` implementation](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/apk/ZipUtils.java#L96-L175)). `V1SchemeUtil.getEocd` rejects an APK when a ZIP64 EOCD locator is present ([`V1SchemeUtil.getEocd`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V1SchemeUtil.java#L262-L281)).

`apksig-go` implements the same important invariant: it scans at most `22 + 0xffff` tail bytes, checks the EOCD signature, and accepts it only when `22 + commentLen` equals the remaining tail length ([`pkg/zip.FindEOCD`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/zip/zip.go#L19-L69)). The Go implementation should parse the EOCD before inspecting a V1 suffix, rather than treating any final `ltlovezh` bytes as channel metadata.

For a source comment of `C` bytes and an encoded channel of `N` bytes, a V1 write is valid only when:

```text
suffixLen = N + 2 + 8
newCommentLen = C + suffixLen
0 < N <= 0xffff
newCommentLen <= 0xffff
```

The upstream writer does not enforce the final bound: it casts the new length to Java `short` ([`writeShort` call sites](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V1SchemeUtil.java#L61-L72), [`existing-comment path`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V1SchemeUtil.java#L94-L113)). A Go writer must reject overflow before writing any bytes.

### 3. Reader behavior is less strict than the ZIP format

`readChannel` reads from the physical end of the file: it checks the last eight bytes for `ltlovezh`, reads the preceding two bytes with `readShort`, then seeks backwards by that value and decodes the channel ([`V1SchemeUtil.readChannel`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V1SchemeUtil.java#L162-L196)). It does not compare the suffix bounds with the EOCD comment length.

There are four compatibility consequences:

1. The stored length is intended as an unsigned 16-bit value, but VasDolly's `readShort` returns a signed Java `short`. A channel byte length from `0x8000` through `0xffff` is read as negative and rejected by `length > 0`. Thus the wire field can represent 65535, but a channel generated with more than 32767 bytes is not readable by VasDolly 3.0.6.
2. The writer checks `String.isEmpty()`, not encoded byte length. An empty string is rejected, but malformed/oversized byte sequences are not validated before the short cast.
3. `new String(bytes, "UTF-8")` uses Java's replacement behavior for malformed UTF-8 rather than reporting invalid bytes, and the returned value is passed through `String.trim()` ([same reader lines](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V1SchemeUtil.java#L175-L186)). Leading/trailing characters recognized by Java `trim()` are therefore not round-tripped.
4. A trailing marker in an unrelated ZIP comment can be mistaken for a channel if the preceding bytes happen to form a positive length; the reader's tail-only search provides no structural proof that the suffix belongs to the EOCD comment.

For generated artifacts that must be readable by the existing VasDolly reader, cap the encoded channel length at 32767 bytes even though the ZIP field itself permits 65535. The Go reader may parse the unsigned field for diagnostics, but should reject malformed bounds and invalid UTF-8 rather than silently replacing bytes. The API should document whether it returns the exact stored channel or deliberately mirrors VasDolly's `trim()`; exact-byte round-trip is safer for a new Go API, while accepting/producing leading or trailing whitespace is not compatible with VasDolly's returned value.

### 4. Existing and repeated channels

For a comment-free APK, VasDolly rewrites the EOCD comment-length field and appends the suffix. For a non-empty comment, it increases the length and writes at the old comment end, preserving the existing comment bytes verbatim ([`writeChannel`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V1SchemeUtil.java#L58-L119)).

The intended duplicate behavior is to detect a trailing V1 marker, read the existing channel, and raise `ChannelExistException` ([`writeChannel` duplicate branch](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V1SchemeUtil.java#L78-L92)). However, the same branch catches `Exception` immediately after throwing, calls `file.delete()`, and then continues to write. In other words, the source contains a destructive error-handling bug, not a meaningful requirement to overwrite/rebuild an existing channel. The Go implementation must preflight a structurally valid suffix and return `ErrChannelExists` without mutating the source or destination.

Only a suffix proven to be inside the EOCD comment should count as an existing V1 channel. A random `ltlovezh` sequence elsewhere in the APK must not trigger duplicate handling.

### 5. Removal semantics

`removeChannelByV1` does not locate or validate a V1 suffix. If the EOCD has any non-empty comment, it sets the EOCD comment length to zero and truncates all comment bytes ([`removeChannelByV1`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V1SchemeUtil.java#L125-L153)). It is a whole-comment removal operation, so an unrelated application comment is lost. A comment-free APK is a no-op.

The Go contract should preserve data: remove only the final, valid V1 suffix, set the EOCD comment length to the remaining prefix length, and truncate exactly the suffix bytes. If no valid V1 suffix exists, leave the archive unchanged and report the chosen not-found/no-op result consistently. This intentionally fixes the upstream data-loss behavior while retaining the VasDolly suffix format.

### 6. V1/JAR verification impact

Android documents V1 as JAR signing and explicitly says V1 signatures do not protect some APK parts such as ZIP metadata ([AOSP V1 overview](https://source.android.com/docs/security/features/apksigning#v1)). Oracle's signed-JAR verification procedure checks the signature over the `.SF` file, manifest digests, and the actual data referenced by manifest entries ([Oracle `Signed JAR file`](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signed_JAR_File), [Oracle `Signature validation`](https://docs.oracle.com/javase/8/docs/technotes/guides/jar/jar.html#Signature_Validation)); it does not make the EOCD comment part of the signed entry data.

Both Go references reflect that boundary:

- `apksig-go/pkg/verifier/v1` parses the central-directory entries, reads `META-INF/MANIFEST.MF`, `.SF`, and signature blocks, and verifies manifest-referenced entry contents; it never reads the EOCD comment ([`v1.Verify`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/verifier/v1/v1.go#L58-L183), [signature verification](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/verifier/v1/v1.go#L185-L275)).
- `avast/apkverifier` verifies each manifest-listed ZIP file through `apkparser`, whose normal path delegates ZIP parsing to Go's `archive/zip` and whose fallback also concerns local-file headers/entries, not the EOCD comment ([`verifyMainManifest`](https://github.com/avast/apkverifier/blob/d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071/schemev1.go#L441-L504), [`OpenZipReader`](https://github.com/avast/apkparser/blob/7fcaee440f681166528e5a582eb628602360b3ef/zipreader.go#L223-L348)).

Therefore, for a V1-only APK, appending/replacing only the EOCD comment preserves JAR/V1 verification because no signed ZIP entry or manifest/signature file changes. Tencent's own V1 writer documents the same operational assumption: after `addChannelByV1`, a second signing pass is unnecessary ([`ChannelWriter.addChannelByV1`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/writer/src/main/java/com/tencent/vasdolly/writer/ChannelWriter.java#L97-L119)).

This does **not** make the operation safe for a mixed V1 + V2/V3 APK. AOSP defines V2 protection over the ZIP entry contents, APK Signing Block, Central Directory, and EOCD ([AOSP v2 integrity-protected contents](https://source.android.com/docs/security/features/apksigning/v2#integrity-protected-contents)); changing the EOCD comment changes a protected section and invalidates V2/V3 verification. AOSP also documents rollback protection: when V2 is listed in `X-Android-APK-Signed`, a verifier must not accept a V1-only fallback after the stronger signature is missing/invalid ([AOSP v2 rollback protections](https://source.android.com/docs/security/features/apksigning/v2#rollback-protections)). Consequently, V1 mode should be selected only for V1-only inputs; auto detection must prefer V3/V2 when present, and the CLI/API must not claim that a V1 comment mutation preserves mixed-scheme APK validity.

## Implementation contract for the Go V1 path

The following contract is the compatibility target for the implementation:

### Write

1. Parse a regular EOCD using the exact-to-EOF invariant; reject malformed EOCDs and ZIP64 APKs for the V1 path.
2. Require a non-empty Go string, validate it as UTF-8, encode it once to bytes, and use the encoded byte count in both the suffix length field and the EOCD comment-length calculation.
3. Limit the encoded channel to 32767 bytes when the output must be readable by VasDolly 3.0.6. Always enforce `existingCommentLen + len(channelBytes) + 10 <= 65535`.
4. Preserve the original EOCD comment byte-for-byte and append `channelBytes || uint16LE(len(channelBytes)) || []byte("ltlovezh")`.
5. Detect an existing valid V1 suffix within the EOCD comment before writing; return `ErrChannelExists` and leave all bytes unchanged. Never reproduce the upstream delete-and-continue branch.
6. Write to an independent output/temporary file so a failed operation cannot corrupt the base APK.

### Read

1. Locate and validate EOCD first; inspect only the EOCD comment's final eight bytes and the preceding unsigned little-endian length field.
2. Require the suffix to fit wholly within the declared comment and require a positive length. Reject invalid UTF-8 instead of Java replacement decoding.
3. Return the exact decoded channel bytes for round-trip stability; document that this differs from VasDolly's `trim()` behavior for leading/trailing whitespace.

### Remove

1. Remove only a valid final V1 suffix and preserve the remaining comment bytes exactly.
2. Update the EOCD comment length and truncate only the suffix; no EOCD/CD offsets otherwise change.
3. If no valid suffix exists, do not rewrite the APK; use a stable not-found/no-op error policy at the public API boundary.

### Verification and mode selection

1. Verify a V1-only output with the Go V1 verifier in tests; success should be unchanged before and after comment injection.
2. Treat an existing V2/V3 Signing Block as a mode-selection boundary. Do not use V1 comment injection on mixed-scheme APKs unless the caller explicitly accepts invalidating the stronger scheme.
3. Keep V4 `.idsig` out of the V1 compatibility claim: modifying the APK requires a caller-managed V4 regeneration.

## Acceptance cases derived from the sources

- Empty comment and non-empty comment: output suffix is identical except for the original comment prefix and the EOCD length field.
- Multibyte UTF-8 channel: stored length equals `len([]byte(channel))`, not rune count; a valid output round-trips exact bytes.
- Channel length 32767: readable by VasDolly; channel length 32768: reject in compatibility mode with a clear error.
- Existing comment near 65535 bytes: reject when the complete new comment exceeds 65535, without modifying the APK.
- Existing valid V1 suffix: duplicate write returns `ErrChannelExists` and preserves source bytes.
- Existing ordinary comment without a V1 suffix: remove leaves it intact; write appends the suffix.
- Malformed/truncated marker, invalid length, invalid UTF-8, fake marker outside the EOCD comment, and ZIP64 input: reject or no-op according to the API error policy, never guess a channel.
- V1-signed APK: JAR/V1 verification remains valid after comment-only injection; mixed V1+V2/V3 input is not considered V2/V3-valid after V1 mutation.
