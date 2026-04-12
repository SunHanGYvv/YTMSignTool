# Changelog / 变更日志

All notable changes to **YTMSignTool** are documented in this file. Version numbers match `[package].version` in [`Cargo.toml`](Cargo.toml).

本文件记录 **YTMSignTool** 的重要变更。版本号与 [`Cargo.toml`](Cargo.toml) 中 `[package].version` 一致。

The format is inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Keep a Changelog（中文）](https://keepachangelog.com/zh-CN/1.1.0/). Categories: **Added**, **Changed**, **Fixed**, **Removed**, **Security** — and the Chinese equivalents below.

格式参考 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) 与 [Keep a Changelog（中文）](https://keepachangelog.com/zh-CN/1.1.0/)。英文分类：**Added**、**Changed**、**Fixed**、**Removed**、**Security**；中文对应：**新增**、**变更**、**修复**、**移除**、**安全**。

---

## [0.1.0] - 2026-04-12

### Added

- CLI for **YTM32** secure boot: `sign`, `verify`, `keygen`, `info`, `convert`.
- Intel HEX, Motorola S19/SREC, and raw BIN; parses the BVT and secure-boot section metadata, **AES-CMAC** per section, writes signatures back into the image.
- Hardware: **YTM32B1ME05** series.
- Keys described in JSON (`keygen` from firmware with BVT or an empty 32-slot template).
- GitHub Actions: `ci.yml` (build & tests), `release.yml` (on `v*` tags: Linux musl tarball and Windows executable).

After you publish the matching git tag, binaries and notes appear on the GitHub **Releases** page.

### 新增

- 面向 **YTM32** 安全启动的命令行：`sign`、`verify`、`keygen`、`info`、`convert`。
- 支持 Intel HEX、Motorola S19/SREC、原始 BIN；解析 BVT 与安全启动段元数据，按段 **AES-CMAC** 签名并写回镜像。
- 适配硬件：**YTM32B1ME05** 系列。
- 密钥以 JSON 描述（`keygen` 可从带 BVT 的固件或 32 槽位空模板生成）。
- GitHub Actions：`ci.yml`（构建与测试）、`release.yml`（`v*` 标签发布 Linux musl 压缩包与 Windows 可执行文件）。

发布对应标签后，可在 GitHub **Releases** 页面查看该版本的制品与说明。
