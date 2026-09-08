# VasDolly-go

[English](README.md) | 简体中文

纯 Go 实现的 VasDolly 多渠道信息读写库和命令行工具。它只修改渠道信息，不重新签名 APK；基础 APK 保持不变，每个渠道输出独立文件。

支持：

- V1：在 ZIP EOCD comment 末尾写入 `channel UTF-8 bytes + uint16LE(length) + ltlovezh`。
- V2/V3：在 APK Signing Block 中写入 VasDolly pair `0x881155ff`（或 Walle / 自定义 Block ID），保留其他 pair 和原有签名 payload。
- `Pack`、`ReadChannel`、`ReadChannelWithBlockID`、`RemoveChannel` 以及带原子写入和 worker pool 的 `PackFiles`。
- `vasdolly put|get|remove` CLI。

## Library

```go
var output bytes.Buffer
// 默认使用 VasDolly (0x881155ff)
err := vasdolly.Pack(input, inputSize, "huawei", &output,
    vasdolly.TransformOptions{Mode: vasdolly.ModeAuto})

// 写入 Walle 兼容格式（自动生成 JSON payload）或自定义 Block ID
err = vasdolly.Pack(input, inputSize, "huawei", &output,
    vasdolly.TransformOptions{Mode: vasdolly.ModeV2, BlockID: vasdolly.WallePairID})

// 读取指定 block-id 的渠道信息（为 0 时按 VasDolly -> Walle -> V1 顺序自动探测）
channel, err := vasdolly.ReadChannelWithBlockID(input, inputSize, vasdolly.WallePairID)
```

`ModeAuto` 优先选择 V3/V2 Signing Block，否则使用 V1。设置 `VerifyInput: true` 可在写入前验证所选签名方案；结构检查始终执行。V1 模式拒绝带有 V2/V3 签名的混合 APK，避免破坏更强签名。

## CLI

```text
vasdolly put -c "huawei,xiaomi" app.apk dist/
vasdolly put -c channels.txt --mode v1 app.apk dist/

# 使用 Walle 兼容的 JSON 渠道信息
vasdolly put -c channels.txt --mode v2 --block-id Walle app.apk dist/
vasdolly get -c huawei-app.apk
vasdolly get -c huawei-app.apk --block-id Walle
vasdolly get -s huawei-app.apk
vasdolly remove -c huawei-app.apk cleaned.apk
vasdolly remove -c huawei-app.apk --block-id Walle cleaned.apk
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
├── cmd/vasdolly/   # 命令行入口
├── internal/core/  # APK 解析、签名检测与渠道转换实现
├── docs/           # 设计、研究和维护文档
└── vasdolly.go     # 稳定的公共 Go 接口
```

根包保留 `github.com/CodeIdeal/VasDolly-go` import path；不可供外部项目直接依赖的实现放在 `internal/core`。项目没有独立的第二套公共包，因此不创建 `pkg/`。

运行时依赖 `github.com/agusibrahim/apksig-go v1.1.0`，不调用 Java、Android SDK、`apksigner` 或 CGO。
