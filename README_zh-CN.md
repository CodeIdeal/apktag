# apktag

[English](README.md) | 简体中文

纯 Go 实现的 APK 多渠道信息读写库和命令行工具，兼容 VasDolly、Walle 以及自定义 Block ID。它只读取和修改渠道信息，不重新签名 APK；基础 APK 保持不变，每个渠道输出独立文件。

支持：

- V1：在 ZIP EOCD comment 末尾写入 `channel UTF-8 bytes + uint16LE(length) + ltlovezh`。
- V2/V3：在 APK Signing Block 中写入 VasDolly pair `0x881155ff`（或 Walle / 自定义 Block ID），保留其他 pair 和原有签名 payload。
- `Pack`、`ReadChannel`、`ReadChannelWithBlockID`、`RemoveChannel` 以及带原子写入和 worker pool 的 `PackFiles`。
- `apktag put|get|remove` CLI。

## Library

导入 `github.com/CodeIdeal/apktag`，使用 `apktag` 包。

```go
var output bytes.Buffer
// 默认使用 VasDolly (0x881155ff)
err := apktag.Pack(input, inputSize, "huawei", &output,
    apktag.TransformOptions{Mode: apktag.ModeAuto})

// 写入 Walle 兼容格式（自动生成 JSON payload）或自定义 Block ID
err = apktag.Pack(input, inputSize, "huawei", &output,
    apktag.TransformOptions{Mode: apktag.ModeV2, BlockID: apktag.WallePairID})

// 读取指定 block-id 的渠道信息（为 0 时按 VasDolly -> Walle -> V1 顺序自动探测）
channel, err := apktag.ReadChannelWithBlockID(input, inputSize, apktag.WallePairID)
```

`ModeAuto` 优先选择 V3/V2 Signing Block，否则使用 V1。设置 `VerifyInput: true` 可在写入前验证所选签名方案；结构检查始终执行。V1 模式拒绝带有 V2/V3 签名的混合 APK，避免破坏更强签名。

### 日志输出 (Logging)

作为 Go 依赖库使用时，默认静默无输出。若需输出与 VasDolly 格式一致的日志，可通过配置全局或单个操作的 Logger：

```go
// 输出与 VasDolly 一致的日志到标准输出
apktag.SetOutput(os.Stdout)

// 或自定义实现 Logger 接口
apktag.SetLogger(customLogger)

// 或在单次操作中传递 Logger
opts := apktag.TransformOptions{
    Mode:   apktag.ModeAuto,
    Logger: customLogger,
}
```

## CLI

从当前源码构建 CLI：

```sh
go build -o apktag ./cmd/apktag
./apktag --help
```

```text
apktag put -c "huawei,xiaomi" app.apk dist/
apktag put -c channels.txt --mode v1 app.apk dist/

# 使用 Walle 兼容的 JSON 渠道信息
apktag put -c channels.txt --mode v2 --block-id Walle app.apk dist/
apktag get -c huawei-app.apk
apktag get -c huawei-app.apk --block-id Walle
apktag get -s huawei-app.apk
apktag remove -c huawei-app.apk cleaned.apk
apktag remove -c huawei-app.apk --block-id Walle cleaned.apk
```

`channels.txt` 每行一个渠道；空行和首尾空白会被忽略，重复渠道只保留第一次出现的值。V4 `.idsig`、AAB、APK 重签名和 Source Stamp 重新生成不在范围内；修改带 V4 的 APK 后由调用方负责重新生成 sidecar。

V2/V3 打包时，`--block-id` 支持 `VasDolly`（默认值 `0x881155FF`）、`Walle`（`0x71777777`）或自定义 32 位十六进制 ID。Walle 的 payload 必须是包含非空字符串 `channel` 字段的 JSON 对象；读取已有渠道包时允许存在额外字段。

## Development

```text
go test ./...
go vet ./...
```

项目按 Go 社区常见布局组织：

```text
.
├── cmd/apktag/     # 命令行入口
├── internal/core/  # APK 解析、签名检测与渠道转换实现
├── docs/           # 设计、研究和维护文档
└── apktag.go       # 稳定的公共 Go 接口
```

根包使用 `github.com/CodeIdeal/apktag` import path；不可供外部项目直接依赖的实现放在 `internal/core`。项目没有独立的第二套公共包，因此不创建 `pkg/`。

运行时依赖 `github.com/agusibrahim/apksig-go v1.1.0`，不调用 Java、Android SDK、`apksigner` 或 CGO。

## 外部工具兼容性测试

可选的黑盒测试会使用 VasDolly 和 Walle JAR，对同一组生成的 APK 做交叉读写、删除、签名组合、渠道和 ZIP comment 边界、Signing Block 边界、批量输入、元数据共存、损坏 APK 以及 MD5/结构对比验证。

```sh
VASDOLLY_JAR=/path/to/VasDolly.jar \
WALLE_JAR=/path/to/walle.jar \
go test -tags=interop ./internal/core -run TestInterop -count=1 -v -timeout=20m
```

设置 `APKSIGNER` 可额外执行独立签名校验；设置 `INTEROP_ARTIFACT_DIR` 可保留失败用例的文件和命令日志。参考 JAR 仅用于测试，不会下载或提交到仓库。
