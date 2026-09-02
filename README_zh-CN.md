# VasDolly-go

[English](README.md) | 简体中文

纯 Go 实现的 VasDolly 多渠道元数据读写库和命令行工具。它只修改渠道元数据，不重新签名 APK；基础 APK 保持不变，每个渠道输出独立文件。

支持：

- V1：在 ZIP EOCD comment 末尾写入 `channel UTF-8 bytes + uint16LE(length) + ltlovezh`。
- V2/V3：在 APK Signing Block 中写入 VasDolly pair `0x881155ff`，保留其他 pair 和原有签名 payload。
- `Pack`、`ReadChannel`、`RemoveChannel` 以及带原子写入和 worker pool 的 `PackFiles`。
- `vasdolly put|get|remove` CLI。

## Library

```go
var output bytes.Buffer
err := vasdolly.Pack(input, inputSize, "huawei", &output,
    vasdolly.TransformOptions{Mode: vasdolly.ModeAuto})
```

`ModeAuto` 优先选择 V3/V2 Signing Block，否则使用 V1。设置 `VerifyInput: true` 可在写入前验证所选签名方案；结构检查始终执行。V1 模式拒绝带有 V2/V3 签名的混合 APK，避免破坏更强签名。

## CLI

```text
vasdolly put -c "huawei,xiaomi" app.apk dist/
vasdolly put -c channels.txt --mode v1 app.apk dist/
vasdolly get -c huawei-app.apk
vasdolly get -s huawei-app.apk
vasdolly remove -c huawei-app.apk cleaned.apk
```

`channels.txt` 每行一个渠道；空行和首尾空白会被忽略，重复渠道只保留第一次出现的值。V4 `.idsig`、AAB、APK 重签名和 Source Stamp 重新生成不在范围内；修改带 V4 的 APK 后由调用方负责重新生成 sidecar。

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
