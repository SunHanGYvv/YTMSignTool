# YTMSignTool

[![GitHub](https://img.shields.io/badge/GitHub-YTMSignTool-181717?logo=github)](https://github.com/SunHanGYvv/YTMSignTool) [![YTMicro](https://img.shields.io/badge/YTMicro-ytmicro.com-0066CC)](https://www.ytmicro.com/) [![Rust](https://img.shields.io/badge/rust-2021%20edition-orange.svg)](https://www.rust-lang.org/) [![CI](https://github.com/SunHanGYvv/YTMSignTool/actions/workflows/ci.yml/badge.svg)](https://github.com/SunHanGYvv/YTMSignTool/actions/workflows/ci.yml) [![Tests](https://img.shields.io/github/actions/workflow/status/SunHanGYvv/YTMSignTool/ci.yml?label=tests&logo=github)](https://github.com/SunHanGYvv/YTMSignTool/actions/workflows/ci.yml) [![GitHub Release](https://img.shields.io/github/v/release/SunHanGYvv/YTMSignTool?label=version&logo=github)](https://github.com/SunHanGYvv/YTMSignTool/releases) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Command-line tool for signing and verifying **YTM32** MCU firmware for **secure boot**. It parses Intel HEX, Motorola S19/SREC, or raw BIN images, reads the Boot Vector Table (BVT) and secure-boot section metadata, computes **AES-CMAC** signatures per section, writes them back into the image BVT, and can convert between HEX, BIN, and S19.

## Supported hardware

- YTM32B1ME05 series

## Features

- **sign** — Sign firmware with a JSON key file; emit `hex`, `bin`, or `s19`
- **verify** — Validate the BVT, secure-boot group, per-section descriptors, and (optionally) CMAC values
- **keygen** — Generate a key JSON template from firmware that includes a BVT, or emit an empty 32-slot template
- **info** — Print BVT and secure-boot configuration
- **convert** — Convert between HEX, BIN, and S19

## Requirements

- [Rust](https://www.rust-lang.org/) toolchain (edition **2021**, **stable** recommended)

## Installation

From the repository root:

```bash
cargo build --release
```

The binary is written to `target/release/ytm_sign_tool`. Optionally install it into `~/.cargo/bin`:

```bash
cargo install --path .
```

## Usage

```text
ytm_sign_tool [OPTIONS] <COMMAND>
```

Global options:

| Option | Description |
|--------|-------------|
| `-q`, `--slient` | Quiet mode (disables logging; spelling matches the program) |
| `-h`, `--help` | Help |
| `-V`, `--version` | Version |

Run `ytm_sign_tool <command> --help` for subcommand details.

### Examples

Sample images and keys live under `images/` and `config/sign_keys.json`. Replace them with your own firmware and secrets for production.

**Sign** (default output in the current directory: `./<input-stem>_signed.<ext>`):

```bash
ytm_sign_tool sign -i images/unsigned.s19 -k config/sign_keys.json
```

**Sign with explicit format and output directory:**

```bash
ytm_sign_tool sign -i images/unsigned.hex -k config/sign_keys.json -o ./out/ -t s19
```

For **BIN** output, use `--base` for the load address and `--size` for the length. If `--size` is omitted, the tool infers length from the highest address used by the firmware and CMAC.

**Verify** (when keys are supplied, CMACs for each section are verified):

```bash
ytm_sign_tool verify -i images/signed.s19 -k config/sign_keys.json
```

**Generate a key template from firmware (with BVT):**

```bash
ytm_sign_tool keygen -i images/unsigned.s19 -o ./my_keys.json
```

Without `-i`, `keygen` writes an empty 32-slot template for you to fill in manually.

**Print secure-boot metadata:**

```bash
ytm_sign_tool info -i images/signed.s19
```

If the secure-boot group encrypts section configuration (`encrypt=true`), run `info` with `-k` and the keys JSON.

**Convert between formats:**

```bash
ytm_sign_tool convert -i images/unsigned.hex -o ./out/fw.bin -t bin --base 0x4000
```

## Key file format

Keys are stored as JSON:

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

| Field | Description |
|-------|-------------|
| `index` | Key slot index (`u8`), must match the section `key_slot` in the image |
| `rindex` | Reverse index paired with `index` (filled when `keygen` produces the template) |
| `key` | Hex-encoded key bytes; length must match the section AES size (128 / 192 / 256 bit) |

See `config/sign_keys.json` for a complete example. **Do not commit production keys to the repository.**

## Logging

Outside quiet mode, logging uses `env_logger`:

```bash
RUST_LOG=debug ytm_sign_tool verify -i images/signed.s19 -k config/sign_keys.json
```

## Development

```bash
cargo test
cargo clippy
```

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Issues and pull requests are welcome. Please keep the scope of changes tight and add test coverage where practical.
