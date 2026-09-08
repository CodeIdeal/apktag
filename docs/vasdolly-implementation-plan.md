# 纯 Go VasDolly 多渠道打包实现计划

## Summary

在当前仓库基础上实现一个 `github.com/CodeIdeal/VasDolly-go` Go module，提供库与 CLI 两种使用方式：

- 支持 VasDolly 兼容的 V1、V2、V3 渠道写入和读取。
- 默认自动检测 APK 签名模式，也允许显式指定 `v1` 或 `v2`；`v2` 模式覆盖 V2/V3 Signing Block。
- 基础 APK 始终只读，每个渠道生成独立的 `<channel>-<base>.apk`。
- 运行时只使用 Go 代码和 Go module 依赖，不调用 Java、Android SDK、`apksigner` 或 CGO。
- 直接依赖 `apksig-go`；`apkverifier` 和 `apkparser` 作为格式、验证和兼容性参考。

## 核心实现

### 公共 Go API

提供以下稳定接口：

```go
type Mode string

const (
    ModeAuto Mode = "auto"
    ModeV1   Mode = "v1"
    ModeV2   Mode = "v2" // 同时适用于 V2/V3 Signing Block
)

type TransformOptions struct {
    Mode         Mode
    BlockID      uint32 // 0 默认使用 VasDolly (0x881155ff)；支持 Walle (0x71777777) 或自定义 32 位 ID
    VerifyInput  bool   // true 时验证输入签名；Go 零值为 false
}

type BatchOptions struct {
    TransformOptions
    OutputDir     string
    OutputPattern string // 默认 "{channel}-{base}.apk"
    Overwrite     bool
    Workers       int
}

type Detection struct {
    Mode     Mode // V3 优先于 V2，V2 优先于 V1
    HasV1    bool
    HasV2    bool
    HasV3    bool
    HasV31   bool
    Verified bool
    Warnings []string
}

type Artifact struct {
    Channel string
    Path    string
    Mode    Mode
}

const (
    ChannelPairID uint32 = 0x881155ff
    WallePairID   uint32 = 0x71777777
)

func Detect(r io.ReaderAt, size int64) (Detection, error)
func ReadChannel(r io.ReaderAt, size int64) (string, error)
func ReadChannelWithBlockID(r io.ReaderAt, size int64, blockID uint32) (string, error)
func Pack(r io.ReaderAt, size int64, channel string, w io.Writer, opts TransformOptions) error
func RemoveChannel(r io.ReaderAt, size int64, w io.Writer, opts TransformOptions) error
func PackFiles(basePath string, channels []string, opts BatchOptions) ([]Artifact, error)
```

文件 API 负责打开输入、创建临时文件、原子 rename 和批量输出；底层 Reader/Writer API 便于内存、HTTP 或其他 `io.ReaderAt` 场景集成。

### V1 渠道格式

- 使用 UTF-8 渠道字符串。
- 在 EOCD comment 末尾追加：`channel bytes + uint16LE(channel byte length) + "ltlovezh"`。
- 保留原有 ZIP comment。
- ZIP comment 总长度超过 `65535` 时返回错误。
- 读取时校验 magic、长度边界和 UTF-8。
- 删除时只移除 VasDolly 渠道尾部；保留原有 comment 内容。

### V2/V3 渠道格式与多 Block ID 支持

- 默认使用 VasDolly 固定 pair ID：`0x881155ff`；渠道 value 为 UTF-8 原始字节，不附加额外编码。
- 兼容美团 Walle pair ID：`0x71777777`；写入时自动封装为 JSON `{"channel":"<name>"}`，读取与校验时要求非空 `channel` 字符串并允许额外元数据字段。
- 支持调用方指定的自定义 32 位十六进制 pair ID，以原始 UTF-8 字符串存储渠道信息。
- 使用 `apksig-go/pkg/zip` 和 `pkg/apksigblock` 定位 EOCD、Signing Block、中央目录和原始内容。
- 重建 Signing Block 时：
  - 保留所有未知 ID-value pair 及其顺序；
  - 检测已有目标 channel pair 并返回 `ErrChannelExists`，避免重复；
  - 移除旧 padding pair 后重新计算 padding；
  - 保证 Signing Block 按 4096 字节边界对齐；
  - 更新 EOCD 中的中央目录偏移；
  - 不改变 APK 内容区、中央目录条目内容或已有 V2/V3 签名 payload。
- 无 Signing Block 时，显式 `v2` 模式报错；`auto` 模式回退到 V1，前提是 APK 存在有效 V1 签名。

### 模式检测与删除语义

- `Detect` 使用 `apksig-go/pkg/apkverifier` 验证可用签名，并按 V3/V3.1 → V2 → V1 选择最高模式。
- `VerifyInput` 显式设为 `true` 时验证输入签名；Go bool 的零值保持为跳过签名验证，只执行结构检查。
- `ReadChannel` 默认按 VasDolly pair (`0x881155ff`) → Walle pair (`0x71777777`) → V1 ZIP comment 顺序读取；`ReadChannelWithBlockID` 支持指定任意 block ID。
- `RemoveChannel` 在 `auto` 模式下清理目标 pair（默认 VasDolly pair）和 V1 尾部 marker，避免留下第二个渠道来源；显式模式只处理指定模式与 Block ID。
- 基础 APK 已存在渠道信息时，`Pack` 返回 `ErrChannelExists`，不在已有渠道上继续叠加。

### 输入、文件名和批量行为

- 渠道字符串不能为空；渠道文件按 UTF-8 一行一个渠道，去除首尾空白、忽略空行、首行可去除 UTF-8 BOM。
- 逗号列表和渠道文件都支持；重复渠道去重并保持第一次出现的顺序。
- 渠道值写入 payload 时保留解析后的完整字符串。
- 为防止路径穿越，渠道不得包含 `/`、`\\`、NUL 或控制字符。
- 默认输出命名为 `<channel>-<base>.apk`；`base` 为输入文件名去除 `.apk` 后的部分。
- 单渠道输出可指定精确 `.apk` 路径；批量输出使用目录。
- 批量任务使用有界 worker pool，结果按输入渠道顺序返回；单个输出失败不会修改输入 APK。
- 每个输出先写同目录临时文件，完成后执行 flush、关闭并原子替换；默认不覆盖已有文件，`Overwrite=true` 才允许覆盖。

## CLI

新增 `cmd/vasdolly`，兼容 VasDolly 的主要命令：

```text
vasdolly put -c "channel1,channel2" base.apk out-dir/
vasdolly put -c channels.txt base.apk out-dir/
vasdolly put --mode v1 -c channels.txt base.apk out-dir/
vasdolly put --mode v2 --block-id Walle -c channels.txt base.apk out-dir/

vasdolly get -c channel.apk
vasdolly get -c channel.apk --block-id Walle
vasdolly get -s channel.apk

vasdolly remove -c channel.apk
vasdolly remove --mode v2 channel.apk cleaned.apk
vasdolly remove --block-id Walle channel.apk cleaned.apk
```

约定：

- `put -c` 接受逗号列表或渠道文件路径；
- `get -c` 读取渠道；
- `get -s` 输出签名模式和验证状态；
- `remove -c` 默认原地生成安全临时文件后替换原文件；
- `--mode auto|v1|v2` 覆盖自动检测；
- `--block-id VasDolly|Walle|<hex>` 指定 Signing Block ID（默认 `VasDolly`）；
- `--out`、`--pattern`、`--overwrite`、`--workers`、`--no-verify` 为 Go CLI 扩展参数；
- 命令错误使用非零退出码，并输出可定位的结构、签名或渠道错误。

## 测试与验收

### 单元测试

覆盖：

- 无 ZIP comment、已有普通 comment 的 V1 写入与读取；
- V1 marker、长度字段、UTF-8、comment 溢出；
- V1 删除后原始 comment 恢复；
- V2/V3 Signing Block pair 插入、替换、删除；
- 未知 pair、source-stamp、V4 等 pair 保留；
- padding 重建、4096 对齐、EOCD/CD 偏移更新；
- malformed EOCD、ZIP64、截断 Signing Block、非法 pair length；
- 空渠道、重复渠道、非法文件名字符、已存在渠道；
- 原子输出、覆盖策略和并发批量结果。

### 集成与互操作

- 构造最小 ZIP/APK fixture，覆盖 V1-only、V2-only、V3-only、V1+V2/V3。
- 使用 `apksig-go/pkg/apkverifier` 验证写入前后的 APK 签名仍有效。
- 使用 `apksig-go` 读取生成的 Signing Block，并断言渠道 pair 值。
- 增加可选 `interop` 测试：当本机存在 Android `apksigner` 时，验证生成 APK 可被其识别；缺少工具时测试自动跳过。
- 测试多渠道批量输出、文件名 `<channel>-<base>.apk` 和输入文件字节不变。

### 文档

新增 README，说明：

- V1/V2/V3 格式和 Android 兼容范围；
- Go API 和 CLI 示例；
- 渠道文件格式；
- V4 `.idsig` 不在首版范围内，APK 修改后需由调用方重新生成；
- 不支持 AAB、APK 重签名和外部签名密钥管理；
- 依赖版本和升级方式。

## Assumptions

- 首版只实现“注入渠道信息”，不实现 APK 重新签名。
- V2/V3 渠道 pair 位于 Signing Block 中，因此不重新计算原有 V2/V3 签名内容摘要。
- V4 `.idsig`、APK Source Stamp 的重新生成不属于首版；已有 Signing Block pair 会尽量原样保留。
- `apkverifier` 与 `apkparser` 仅作为行为和格式参考，不在首版中处理 license/attribution 议题。
- 当前仓库已有初始化 commit，后续实现从现有 `main` 分支继续。
