# YTMSignTool

[![GitHub](https://img.shields.io/badge/GitHub-YTMSignTool-181717?logo=github)](https://github.com/SunHanGYvv/YTMSignTool) [![YTM](https://img.shields.io/badge/YTMicro-ytmicro.com-0066CC)](https://www.ytmicro.com/) [![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org/) [![CI](https://github.com/SunHanGYvv/YTMSignTool/actions/workflows/ci.yml/badge.svg)](https://github.com/SunHanGYvv/YTMSignTool/actions/workflows/ci.yml) [![Tests](https://img.shields.io/github/actions/workflow/status/SunHanGYvv/YTMSignTool/ci.yml?label=tests&logo=github)](https://github.com/SunHanGYvv/YTMSignTool/actions/workflows/ci.yml) [![GitHub Release](https://img.shields.io/github/v/release/SunHanGYvv/YTMSignTool?label=version&logo=github)](https://github.com/SunHanGYvv/YTMSignTool/releases) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

面向 **YTM32** 系列 MCU **安全启动（Secure Boot）** 的命令行固件签名与校验工具。支持解析 Intel HEX、Motorola S19/SREC 以及原始 BIN，读取引导向量表（BVT）与安全启动段元数据，按段计算 **AES-CMAC** 签名并写回镜像 BVT ，并可在 HEX、BIN、S19 之间转换。

## 适配硬件

- YTM32B1ME05系列

## 功能

- **sign** — 使用 JSON 密钥文件签名，输出 `hex` / `bin` / `s19`
- **verify** — 校验 BVT、安全启动组、各段描述，以及（可选）CMAC
- **keygen** — 从带 BVT 固件生成密钥 JSON 模板，或输出 32 槽位空模板
- **info** — 打印 BVT 与安全启动配置
- **convert** — HEX、BIN、S19 互转

## 环境要求

- [Rust](https://www.rust-lang.org/) 工具链（**edition 2021**，建议 **stable**）

## 安装

在仓库根目录执行：

```bash
cargo build --release
```

可执行文件位于 `target/release/ytm_sign_tool`。也可安装到 `~/.cargo/bin`：

```bash
cargo install --path .
```

## 用法

```text
ytm_sign_tool [OPTIONS] <COMMAND>
```

全局选项：

| 选项 | 说明 |
|------|------|
| `-q`, `--slient` | 静默模式（关闭日志；与程序内拼写一致） |
| `-h`, `--help` | 帮助 |
| `-V`, `--version` | 版本 |

子命令详情：`ytm_sign_tool <command> --help`。

### 示例

示例固件与密钥见 `images/`、`config/sign_keys.json`。生产环境请替换为自己的镜像与密钥。

**签名**（默认输出为当前目录下的 `./<输入文件名>_signed.<扩展名>`）：

```bash
ytm_sign_tool sign -i images/unsigned.s19 -k config/sign_keys.json
```

**指定输出格式与目录：**

```bash
ytm_sign_tool sign -i images/unsigned.hex -k config/sign_keys.json -o ./out/ -t s19
```

输出 **BIN** 时，用 `--base` 指定加载基址，`--size` 指定长度；省略 `--size` 时，工具会根据固件与 CMAC 占用到的最高地址推断长度。

**校验**（提供密钥时会校验各段 CMAC）：

```bash
ytm_sign_tool verify -i images/signed.s19 -k config/sign_keys.json
```

**由固件生成密钥模板：**

```bash
ytm_sign_tool keygen -i images/unsigned.s19 -o ./my_keys.json
```

不提供 `-i` 时，`keygen` 会写出 32 槽位空模板供手工填写。

**查看安全启动元数据：**

```bash
ytm_sign_tool info -i images/signed.s19
```

若安全启动组对段配置做了加密（`encrypt=true`），`info` 需配合 `-k` 传入密钥 JSON。

**格式转换：**

```bash
ytm_sign_tool convert -i images/unsigned.hex -o ./out/fw.bin -t bin --base 0x4000
```

## 密钥文件格式

密钥以 JSON 存储：

```json
{
  "keys": [
    {
      "index": 0,
      "rindex": 31,
      "key": "16157E2BA6D2AE288815F7AB3C4FCF09"
    }
  ]
}
```

| 字段 | 说明 |
|------|------|
| `index` | 密钥槽索引（`u8`），须与镜像中段配置的 `key_slot` 一致 |
| `rindex` | 与 `index` 配套的反向序号（`keygen` 生成模板时会填充） |
| `key` | 十六进制密钥材料，长度须与该段声明的 AES 长度一致（128 / 192 / 256 位） |

完整示例见 `config/sign_keys.json`。**勿将生产密钥提交到版本库。**

## 日志

非静默模式下使用 `env_logger`：

```bash
RUST_LOG=debug ytm_sign_tool verify -i images/signed.s19 -k config/sign_keys.json
```

## 开发

```bash
cargo test
cargo clippy
```

## 许可证

本项目采用 [MIT 许可证](LICENSE)。

## 贡献

欢迎提交 Issue 与 Pull Request；请尽量保持改动范围集中，并在可行时用测试覆盖。
