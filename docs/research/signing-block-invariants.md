# Research: APK Signing Block 重写不变量

## 范围与结论

本文记录纯 Go VasDolly 渠道写入器在重写 APK Signing Block 时必须遵守的格式和兼容性约束。目标是只新增渠道元数据，保留 APK 内容、中央目录和已有 V2/V3/V3.1 签名 payload；本文不设计 APK 重新签名，也不把 V4 `.idsig` 作为 APK 内的 Signing Block pair。

研究固定使用以下源码版本：

| 来源 | Revision | 关注内容 |
| --- | --- | --- |
| [Tencent/VasDolly](https://github.com/Tencent/VasDolly/tree/066426280ad8c391bc86eb823b2b8e5f49d80bec) | `066426280ad8c391bc86eb823b2b8e5f49d80bec` (`release 3.0.6`) | Signing Block、渠道 ID、V2/V3 重写 |
| [agusibrahim/apksig-go](https://github.com/agusibrahim/apksig-go/tree/a0389a9d7f83032504713ac6052f85edfb52f64b) | `a0389a9d7f83032504713ac6052f85edfb52f64b` (`v1.1.0`) | Go 解析、验证和 digest |
| [avast/apkverifier](https://github.com/avast/apkverifier/tree/d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071) | `d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071` | Android 兼容的验证边界 |
| [avast/apkparser](https://github.com/avast/apkparser/tree/7fcaee440f681166528e5a582eb628602360b3ef) | `7fcaee440f681166528e5a582eb628602360b3ef` | ZIP entry 读取行为 |
| [AOSP tools/apksig](https://android.googlesource.com/platform/tools/apksig/+/184702d9d18877edf9e5296c4e191cf0aa2b5fbb) | `184702d9d18877edf9e5296c4e191cf0aa2b5fbb` | 官方 Signing Block 工具实现 |
| [AOSP frameworks/base](https://android.googlesource.com/platform/frameworks/base/+/1cdfff555f4a21f71ccc978290e2e212e2f8b168) | `1cdfff555f4a21f71ccc978290e2e212e2f8b168` | Android 验证器和 digest 语义 |

## 格式规范

### Signing Block 布局

Signing Block 紧邻 ZIP Central Directory 之前，不能放在 APK 末尾或 EOCD comment 中。完整布局为：

```text
uint64 LE size_of_block       // 不包含最前面的 8 字节
重复的 ID-value pair
uint64 LE size_of_block       // 与前面的 size 相同
16 bytes "APK Sig Block 42"
Central Directory
EOCD
```

每个 pair 的布局为 `uint64 LE pair_size`、`uint32 LE id` 和 `pair_size - 4` 字节的 value；`pair_size` 不包含自身的 8 字节。官方工具从 `CD offset - 24` 读取 footer，再用 footer size 反推 block 起点，并要求 header/footer 的 size 相同；Go 实现同样保留 pair 顺序并按第一个匹配 ID 查找：[`ApkSigningBlockUtils.java`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/apk/ApkSigningBlockUtils.java#L97-L147)、[`apksigblock/block.go`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apksigblock/block.go#L1-L10)、[`block.go` 的解析与查找](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apksigblock/block.go#L58-L123)。

解析时必须满足：

- block 至少能容纳 8 字节 header、24 字节 footer；
- `pair_size >= 4`，且 pair 的 value 完全位于 payload 内；
- payload 不能留下不足 8 字节的尾部；
- 所有加法、切片和文件偏移计算都要先检查整数溢出。

这些约束对应 AOSP 的 size 检查和 `apksig-go` 的 `parsePairs`；后者明确拒绝截断的 pair length 和越界的 pair value：[`ApkSigningBlockUtils.java`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/apk/ApkSigningBlockUtils.java#L150-L190)、[`parsePairs`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apksigblock/block.go#L93-L112)。

### EOCD 与中央目录

应先定位 regular EOCD，再使用 EOCD 的 Central Directory size 和 offset 字段。`apksig-go` 在文件尾最多扫描 `22 + 0xffff` 字节，并只接受 comment 长度正好覆盖到文件尾的候选 EOCD：[`FindEOCD`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/zip/zip.go#L19-L69)。AOSP 派生实现还要求 `CD offset + CD size == EOCD offset`，防止 Central Directory 与 EOCD 之间存在隐藏数据：[`signingblock.go`](https://github.com/avast/apkverifier/blob/d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071/signingblock/signingblock.go#L287-L342)、[`ApkSigningBlockUtils.getCentralDirOffset`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/apk/ApkSigningBlockUtils.java#L79-L95)。

实现必须拒绝：

- EOCD 不存在、截断或 comment 未覆盖到文件尾；
- Central Directory offset/size 超出文件范围；
- Central Directory 结束位置不等于 EOCD 起点；
- EOCD 后存在未被 comment 长度覆盖的额外字节；
- ZIP64 locator 或 ZIP64 EOCD 所表达的 APK。

## 重写算法

对已有 V2/V3/V3.1 Signing Block，采用下列顺序：

1. 以只读 `ReaderAt` 解析 EOCD、中央目录和 Signing Block，先完成所有结构预检；失败时不得产生部分输出。
2. 保存 `[0, oldBlockStart)` 的原始内容、Central Directory 原始字节和 EOCD comment；不要重新生成 ZIP entry 或中央目录。
3. 按原始顺序保存所有非 padding pair 的 ID 和 value；已有 VasDolly channel pair 时返回 `ErrChannelExists`，没有时在 padding 前插入一个 `0x881155ff` pair。
4. 删除旧的 verity padding pair，依据新 pair 总长度重新计算一个合法的 padding pair。
5. 生成新的 header、pair payload、重复 size footer 和 magic；header/footer 的 `size_of_block` 必须相同。
6. 设 `delta = newBlockLen - oldBlockLen`，将磁盘上的 EOCD Central Directory offset 更新为 `oldCDOffset + delta`，并输出 `prefix || newBlock || oldCD || patchedEOCD`。
7. 输出只写到独立临时文件，flush、关闭并原子 rename；输入 APK 保持字节不变。

VasDolly 的 `getApkSectionInfo` 以 Signing Block、中央目录和 EOCD 为三个独立 section，`IdValueWriter` 再把新 block 插入原位置；其生成器也只重建 block 并调整 section 偏移：[`V2SchemeUtil.getApkSectionInfo`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V2SchemeUtil.java#L127-L169)、[`V2SchemeUtil.generateApkSigningBlock`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V2SchemeUtil.java#L213-L290)、[`IdValueWriter`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/writer/src/main/java/com/tencent/vasdolly/writer/IdValueWriter.java#L45-L171)。

V2/V3 digest 不覆盖 Signing Block 自身，而覆盖 Signing Block 之前的内容、Central Directory 和 EOCD。验证 digest 时必须复制 EOCD，并把副本中 `[16:20]` 的 Central Directory offset 临时改成 Signing Block 起点；不能修改输出文件中的真实 offset，也不能把新 block 纳入 digest：[`apkverifier.go`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apkverifier/apkverifier.go#L79-L87)、[`verifyContentDigests`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apkverifier/apkverifier.go#L232-L260)、[`apkverifier` integrity verification](https://github.com/avast/apkverifier/blob/d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071/signingblock/signingblock.go#L586-L614)。

因此，插入 channel pair 后，只要 block 起点不变、前缀/CD/EOCD comment 未被改变，并且 EOCD 的真实 CD offset 指向新 CD，原有 V2/V3/V3.1 signature payload 和 content digest 可以继续验证。没有 Signing Block 时，显式 V2/V3 模式应报错；不能通过凭空新增 pair 声称 APK 已签名。

## 重复 ID

不同参考实现对重复 ID 的选择语义不一致：

- `apksig-go` 的 `FindPair` 返回第一个匹配 pair：[`FindPair`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apksigblock/block.go#L115-L123)。
- VasDolly 将 pair 放入 `LinkedHashMap`，相同 ID 的后一个 value 覆盖前一个，同时保留首次插入位置：[`V2SchemeUtil.getAllIdValue`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V2SchemeUtil.java#L46-L80)。
- `avast/apkverifier` 将解析结果写入 map，同一 ID 的后一个 value 会覆盖前一个：[`findSignatureBlocks`](https://github.com/avast/apkverifier/blob/d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071/signingblock/signingblock.go#L462-L548)。

Go 写入器不应依赖 first/last 语义来处理冲突，而应采取 fail-closed 策略：

- `0x881155ff`（VasDolly channel ID）出现多次时返回重复渠道错误，不选择任一 value；
- V2、V3、V3.1、Source Stamp 和其他已知语义 ID 出现多次时返回结构错误，防止验证器之间解释不同；
- 未知 ID 只要各自 pair 合法，就保留原始顺序和 value，不用 map 重排或覆盖；
- ID 为 padding 保留值时必须单独按 padding 规则校验，不能把它当作普通未知 ID。

## Padding 与 4096 对齐

官方 verity padding ID 是 `0x42726577`，padding pair 的 value 应全为零，pair 的总长度至少为 `8 + 4 = 12` 字节；VasDolly 在重建时先移除旧 padding，再以 4096 字节页边界计算新 padding：[`ApkSigningBlockUtils` 常量](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/apk/ApkSigningBlockUtils.java#L14-L21)、[`generateApkSigningBlock` padding](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V2SchemeUtil.java#L234-L265)、[`apksig-go` padding assembler](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/signer/signer.go#L147-L209)。

重建公式：

```text
pairBytes       = Σ(8 + 4 + len(value))
blockWithoutPad = 8 + pairBytes + 8 + 16
```

若 `blockWithoutPad % 4096 == 0`，可以不写 padding pair；否则选择最小的 `paddingValueLen`，使：

```text
(blockWithoutPad + 12 + paddingValueLen) % 4096 == 0
```

当所需 pair 总长度小于 12 时，应增加一个 4096 字节页再计算。不得保留旧 padding 的长度，因为 channel value 改变后旧 padding 很可能失配。若 `0x42726577` pair 的 value 非零，不能未经判断直接删除；应报告保留的未知语义/畸形输入，避免误删真实元数据。

`apksig-go` 源码把同一个数值同时命名为 `IDV4Signature` 和 `IDPaddingPair`，但它自己的 V4 实现明确说明 V4 是 APK 旁边的独立 `.idsig` 文件：[`apksigblock` IDs](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apksigblock/block.go#L28-L38)、[`v4.go` 文件格式](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/verifier/v4/v4.go#L1-L24)。本项目在 APK Signing Block 内只把符合 padding 约束的该 ID 当作 padding。

## EOCD offset 更新

磁盘上的 EOCD `[16:20]` 字段必须指向新 Central Directory 起点：

```text
newCDOffset = oldCDOffset + (newBlockLength - oldBlockLength)
```

这个值必须能表示为 regular ZIP EOCD 的 `uint32`，并且 `newCDOffset + CDSize == newEOCDOffset`。VasDolly 对中央目录和 EOCD 的相邻关系有显式检查：[`getCentralDirOffset`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/apk/ApkSigningBlockUtils.java#L79-L95)；Go 验证器在 digest 计算时则只对 EOCD 副本执行 offset patch：[`patchEOCDCDOffset`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/apkverifier/apkverifier.go#L232-L241)。

实现不得把真实 EOCD offset 永久改成 Signing Block 起点，也不得在验证 digest 时直接修改共享的 EOCD buffer。旧 CD 的 bytes 和 entry offsets 都应原样保留；只有因为 Signing Block 长度变化而产生的 EOCD CD offset 需要更新。

## V4 与 Source Stamp

### V4 `.idsig`

V4 不是 APK Signing Block 中的可保留 pair，而是独立的 `<apk>.idsig` 文件，内容包含 APK digest、4 KiB page hash tree 和对 canonical signed data 的签名：[`v4.go`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/verifier/v4/v4.go#L1-L24)、[`v4signer.go`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/v4signer/v4signer.go#L1-L14)。渠道写入改变 APK 文件内容/长度后，原 `.idsig` 不再对应输出 APK；首版不得复制旧 sidecar 并宣称 V4 仍有效。若调用方需要 V4，必须在最终 APK 上重新生成 `.idsig`。

### Source Stamp

Source Stamp V2 的 Signing Block ID 是 `0x6dff800d`，并且 verifier 同时检查 ZIP entry `stamp-cert-sha256` 与 block 中证书摘要：[`signingblock` IDs](https://github.com/avast/apkverifier/blob/d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071/signingblock/signingblock.go#L34-L44)、[`VerifySourceV2Stamp`](https://github.com/avast/apkverifier/blob/d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071/signingblock/sourcestamp.go#L20-L119)。重写时应原样保留该 pair 和对应 ZIP entry，不修改其 bytes；如果输入存在重复或无法解析的 Source Stamp 语义，应拒绝写入而不是只保留 map 中的一个 value。首版不重新生成 Source Stamp。

## ZIP64 与畸形输入

VasDolly 和 `avast/apkverifier` 都把 ZIP64 APK 作为不支持输入显式拒绝；`apksig-go` 的 ZIP 结构读取主要使用 EOCD 中的 32 位字段，不能把其“能读出字段”误认为已经完整支持 ZIP64：[`VasDolly ZIP64 检查`](https://github.com/Tencent/VasDolly/blob/066426280ad8c391bc86eb823b2b8e5f49d80bec/common/src/main/java/com/tencent/vasdolly/common/V2SchemeUtil.java#L99-L110)、[`apkverifier ZIP64 检查`](https://github.com/avast/apkverifier/blob/d0e1a791cd5ab5b84eb6f271d59ac3b2a9771071/signingblock/signingblock.go#L446-L454)、[`apksig-go ZIP 字段`](https://github.com/agusibrahim/apksig-go/blob/a0389a9d7f83032504713ac6052f85edfb52f64b/pkg/zip/zip.go#L1-L69)。

写入器至少要拒绝以下输入：

- ZIP64 locator、ZIP64 EOCD 或任一 32 位 offset/size 溢出；
- EOCD/CD 不完整、CD 与 EOCD 不相邻、文件尾有额外未声明数据；
- Signing Block magic 缺失、header/footer size 不一致、block 起点为负数；
- pair length 小于 4、pair length 截断、payload 尾部不足 8 字节；
- padding pair 非零或出现无法判定语义的保留 ID；
- 重复 channel/签名/Source Stamp ID；
- 重新计算后 block、CD 或 EOCD offset 超出 regular ZIP 可表示范围。

`apkparser` 的正常 ZIP 路径和 fallback 路径都围绕 entry/local-file-header 读取，而不是为 Signing Block 提供宽松的尾部恢复；因此 malformed 输入应在 Signing Block/EOCD 预检阶段失败，不能依赖通用 ZIP reader 猜测结构：[`OpenZipReader`](https://github.com/avast/apkparser/blob/7fcaee440f681166528e5a582eb628602360b3ef/zipreader.go#L223-L348)。

## 实现验收清单

- [ ] 解析 EOCD 时遵守最多 `64 KiB + 22` 的尾部扫描和 exact-to-EOF comment 约束。
- [ ] 明确拒绝 ZIP64、截断 EOCD、CD 越界、CD/EOCD 不相邻和 Signing Block 尾部多余数据。
- [ ] 校验 Signing Block header/footer size、magic、block 起点、pair length 和整数溢出。
- [ ] 保留所有非 padding pair 的原始 ID/value 顺序；未知 pair 不经过 map 去重或重排。
- [ ] 对 `0x881155ff` 及已知签名/Source Stamp ID 的重复出现 fail closed。
- [ ] 删除旧 padding 后按 4096 字节对齐重建，padding pair 总长度不小于 12，value 全零。
- [ ] 已有 channel pair 时返回 `ErrChannelExists`；没有时在 padding 前插入，且不会生成第二个 channel pair。
- [ ] 磁盘 EOCD CD offset 指向新 CD；digest 校验只在 EOCD 副本中临时 patch 为 block 起点。
- [ ] 保留 Source Stamp pair/entry，但不声称重新生成 Source Stamp；不复制旧 V4 `.idsig`。
- [ ] 输出通过临时文件和原子 rename 完成，失败不会修改基础 APK。
- [ ] 用 `apksig-go` 验证 V2/V3/V3.1 输出，检查 channel pair、CD/EOCD 偏移和未知 pair 字节均符合预期。
