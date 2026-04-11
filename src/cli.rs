use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use log::info;

use crate::crypto::cmac_aes;
use crate::image::{load_image, load_image_with_bin_base};
use crate::keys::SecureKeys;
use crate::types::{SecureGroup, SecureHeader, SecureSection};
use crate::secure_image::{
    generate_key_file, sign_firmware, validate_section_firmware_bounds, verify_firmware,
};

#[derive(Parser, Debug)]
#[command(name = "ytm_sign_tool")]
#[command(author = "HanG")]
#[command(version = "0.1.0")]
#[command(about = "YTM32 MCU Firmware Signing Tool for Secure Boot")]
pub struct Cli {
    /// Slient mode
    #[arg(short = 'q', long = "slient", global = true)]
    pub slient: bool,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    #[command(about = "Sign firmware")]
    Sign {
        #[arg(short, long, help = "Firmware file (HEX, BIN, S19)")]
        input: String,
        #[arg(short, long, help = "Keys configuration (JSON)")]
        keys: String,
        #[arg(
            short,
            long,
            help = "Output file path or directory"
        )]
        output: Option<String>,
        #[arg(
            short = 't',
            long,
            help = "Output format: hex, bin, s19"
        )]
        format: Option<String>,
        #[arg(long, help = "Base address of the binary output (hex, e.g. 0x20000000)")]
        base: Option<String>,
        #[arg(long, help = "Size of the binary output (hex, e.g. 0x80000)")]
        size: Option<String>,
        #[arg(long, help = "Optional secure boot image file path (will be merged into the firmware image)")]
        boot: Option<String>,
    },
    #[command(about = "Verify firmware")]
    Verify {
        #[arg(short, long, help = "Firmware file to verify")]
        input: String,
        #[arg(short, long, help = "Keys configuration (JSON), used to verify CMAC values")]
        keys: Option<String>,
        #[arg(
            long,
            help = "Base address of the original BIN (hex, e.g. 0x4000). If omitted, inferred from BVT position when possible."
        )]
        base: Option<String>,
    },
    #[command(name = "keygen", alias = "genkey", about = "Generate AES keys configuration")]
    Keygen {
        #[arg(
            short,
            long,
            help = "Unsigned firmware (HEX, BIN, S19) that contains key slots and lengths in Secure Boot Section from BVT"
        )]
        input: Option<String>,
        #[arg(
            long,
            help = "BIN load base (hex, e.g. 0x4000) when input is raw binary; if omitted, inferred when possible"
        )]
        base: Option<String>,
        #[arg(
            short,
            long,
            help = "Output JSON file path or directory"
        )]
        output: Option<String>,
    },
    #[command(about = "Display configuration information")]
    Info {
        #[arg(short, long, help = "Firmware file")]
        input: String,
        #[arg(
            short,
            long,
            help = "Keys configuration (JSON); required when secure boot group uses encrypted section config (encrypt=true)"
        )]
        keys: Option<String>,
        #[arg(
            long,
            help = "Base address of the original BIN (hex, e.g. 0x4000). If omitted, inferred from BVT position when possible."
        )]
        base: Option<String>,
    },
    #[command(about = "Convert between HEX, BIN, and S19 formats")]
    Convert {
        #[arg(short, long, help = "Input file")]
        input: String,
        #[arg(
            short,
            long,
            help = "Output file path or directory"
        )]
        output: Option<String>,
        #[arg(
            short = 't',
            long,
            help = "Output format: hex, bin, s19"
        )]
        format: Option<String>,
        #[arg(long, help = "Base address of the binary input/output (hex, e.g. 0x4000)")]
        base: Option<String>,
    },
}

fn infer_format_from_path(path: &str) -> &'static str {
    let p = path.to_lowercase();
    if p.ends_with(".bin") {
        "bin"
    } else if p.ends_with(".s19") || p.ends_with(".srec") {
        "s19"
    } else {
        "hex"
    }
}

fn format_to_extension(fmt: &str) -> &'static str {
    match fmt {
        "bin" => "bin",
        "s19" => "s19",
        _ => "hex",
    }
}

fn ensure_parent_dir_for_file(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if parent.as_os_str().is_empty() {
            return Ok(());
        }
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create output directory {}: {}",
                parent.display(),
                e
            )
        })?;
    }
    Ok(())
}

fn stem_from_input_path(input: &str) -> anyhow::Result<String> {
    Path::new(input)
        .file_stem()
        .and_then(|s| s.to_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Invalid input path: {}", input))
}

fn output_path_means_directory(out: &str) -> bool {
    let t = out.trim();
    if t.is_empty() {
        return false;
    }
    if t.ends_with('/') || t.ends_with('\\') {
        return true;
    }
    Path::new(t).is_dir()
}

fn resolve_output_format(format: Option<&str>, infer_from_path: &str) -> anyhow::Result<String> {
    match format {
        None => Ok(infer_format_from_path(infer_from_path).to_string()),
        Some(f) => {
            let f = f.to_lowercase();
            if f == "hex" {
                Ok("hex".to_string())
            } else if matches!(f.as_str(), "bin" | "s19") {
                Ok(f)
            } else {
                Err(anyhow::anyhow!("Unsupported output format: {}", f))
            }
        }
    }
}

fn resolve_output_path_and_format(
    input: &str,
    output: Option<&str>,
    format: Option<&str>,
    stem_tag: &str,
) -> anyhow::Result<(PathBuf, String)> {
    let stem = stem_from_input_path(input)?;
    match output {
        None => {
            let cwd = std::env::current_dir()?;
            let fmt = resolve_output_format(format, input)?;
            let ext = format_to_extension(&fmt);
            Ok((cwd.join(format!("{stem}_{stem_tag}.{ext}")), fmt))
        }
        Some(out) => {
            if output_path_means_directory(out) {
                let fmt = resolve_output_format(format, input)?;
                let ext = format_to_extension(&fmt);
                Ok((Path::new(out).join(format!("{stem}_{stem_tag}.{ext}")), fmt))
            } else {
                let fmt = resolve_output_format(format, out)?;
                Ok((PathBuf::from(out), fmt))
            }
        }
    }
}

fn resolve_keygen_output_path(input: Option<&str>, output: Option<&str>) -> anyhow::Result<PathBuf> {
    match (input, output) {
        (None, None) => Ok(std::env::current_dir()?.join("keys.json")),
        (Some(inp), None) => {
            let stem = stem_from_input_path(inp)?;
            Ok(std::env::current_dir()?.join(format!("{stem}_keys.json")))
        }
        (None, Some(out)) => {
            if output_path_means_directory(out) {
                Ok(Path::new(out).join("keys.json"))
            } else {
                Ok(PathBuf::from(out))
            }
        }
        (Some(inp), Some(out)) => {
            if output_path_means_directory(out) {
                let stem = stem_from_input_path(inp)?;
                Ok(Path::new(out).join(format!("{stem}_keys.json")))
            } else {
                Ok(PathBuf::from(out))
            }
        }
    }
}

fn parse_hex_or_decimal(s: &str) -> anyhow::Result<u32> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u32::from_str_radix(&s[2..], 16)
            .map_err(|e| anyhow::anyhow!("Failed to parse hexadecimal: '{}': {}", s, e))
    } else {
        s.parse::<u32>()
            .map_err(|e| anyhow::anyhow!("Failed to parse decimal: '{}': {}", s, e))
    }
}

fn should_hint_inferred_binary_base(err_msg: &str) -> bool {
    if err_msg.contains("need to provide key or plain text in image") {
        return false;
    }
    if err_msg.contains("requires key for key_slot") {
        return false;
    }
    if err_msg.contains("Decryption key length should") {
        return false;
    }
    if err_msg.contains("AES key length mismatch") {
        return false;
    }
    if err_msg.contains("section start_addr+length overflow") {
        return false;
    }
    if err_msg.contains("section length") && err_msg.contains("exceeds maximum") {
        return false;
    }
    true
}

fn log_inferred_binary_base_hint(inferred_bin_base: Option<u32>, err_msg: &str) {
    let Some(b) = inferred_bin_base else {
        return;
    };
    if !should_hint_inferred_binary_base(err_msg) {
        return;
    }
    info!(
        "note: binary base address 0x{b:08X} was inferred (no --base); if the image is loaded at another Flash offset, pass --base"
    );
}

fn verify_problems_may_indicate_wrong_load_base(problems: &[String]) -> bool {
    !problems
        .iter()
        .all(|p| p.contains("no key for key_slot"))
}

fn log_inferred_binary_base_hint_for_verify_problems(
    inferred_bin_base: Option<u32>,
    problems: &[String],
) {
    if inferred_bin_base.is_none() || !verify_problems_may_indicate_wrong_load_base(problems) {
        return;
    }
    let b = inferred_bin_base.unwrap();
    info!(
        "note: binary base address 0x{b:08X} was inferred (no --base); if the image is loaded at another Flash offset, pass --base"
    );
}

pub fn cmd_sign(
    input: &str,
    keys_path: &str,
    output: Option<&str>,
    format: Option<&str>,
    base: Option<&str>,
    size: Option<&str>,
    boot: Option<&str>,
) -> anyhow::Result<()> {
    let keys = SecureKeys::from_file(keys_path)?;

    let base_addr = base
        .as_ref()
        .map(|b| parse_hex_or_decimal(b))
        .transpose()?;
    let mut image = load_image(input, base_addr)?;

    if let Some(boot_path) = boot {
        let boot_hex = load_image(boot_path, Some(0x0))?;
        for (&addr, &byte) in &boot_hex.data {
            image.data.insert(addr, byte);
        }
    }

    let signed = sign_firmware(image, &keys)?;

    let (output_path, output_format) = resolve_output_path_and_format(input, output, format, "signed")?;
    ensure_parent_dir_for_file(&output_path)?;

    let bin_region = if output_format == "bin" {
        let bin_base = base
            .as_ref()
            .map(|b| parse_hex_or_decimal(b))
            .transpose()?
            .unwrap_or_else(|| signed.image.get_min_address().unwrap_or(0));
        let bin_size: usize = if let Some(s) = size.as_ref() {
            parse_hex_or_decimal(s)? as usize
        } else {
            let max_firmware_addr = signed.image.get_max_address().unwrap_or(0);
            let max_cmac_addr = signed
                .sb_sections_cmac_order()
                .iter()
                .map(|section| section.cmac_addr.saturating_add(15))
                .max()
                .unwrap_or(0);
            let max_addr = std::cmp::max(max_firmware_addr, max_cmac_addr);
            if max_addr < bin_base {
                return Err(anyhow::anyhow!(
                    "cannot infer BIN size: max address 0x{:08X} < base 0x{:08X}; use --size or adjust --base",
                    max_addr,
                    bin_base
                ));
            }
            (max_addr - bin_base + 1) as usize
        };
        Some((bin_base, bin_size))
    } else {
        None
    };
    signed.write_firmware_format(&output_path, &output_format, bin_region)?;

    info!(
        "sign: {} -> {} (format: {})",
        input,
        output_path.display(),
        output_format
    );

    Ok(())
}

pub fn cmd_verify(
    input: &str,
    keys_path: Option<&str>,
    base: Option<&str>,
) -> anyhow::Result<()> {
    let base_u32 = base
        .map(|b| parse_hex_or_decimal(b))
        .transpose()?;
    let (image, bin_meta) = load_image_with_bin_base(input, base_u32)?;
    let inferred_bin_base = bin_meta.and_then(|(b, inferred)| inferred.then_some(b));

    let keys = if let Some(keys_path) = keys_path {
        Some(SecureKeys::from_file(keys_path)?)
    } else {
        None
    };

    let signed = verify_firmware(image, keys.as_ref()).map_err(|e| {
        let msg = e.to_string();
        log_inferred_binary_base_hint(inferred_bin_base, &msg);
        e
    })?;

    let mut problems: Vec<String> = Vec::new();

    if !signed.header.is_valid() {
        problems.push(format!(
            "BVT marker invalid: 0x{:08X} (expected 0x{:08X})",
            signed.header.get_marker(),
            SecureHeader::default_marker()
        ));
    }
    if !signed.group.is_valid() {
        problems.push(format!(
            "secure boot group marker invalid: 0x{:08X} (expected 0x{:08X})",
            signed.group.get_marker(),
            SecureGroup::default_marker()
        ));
    }

    for (i, section) in signed.sections.iter().enumerate() {
        if !section.is_valid() {
            problems.push(format!(
                "section {}: marker 0x{:04X} invalid (expected 0x{:04X})",
                i, section.get_marker(), SecureSection::default_marker()
            ));
        }
    }

    if let Some(keys) = keys {
        let sorted = signed.sb_sections_cmac_order();

        for (i, section) in sorted.iter().enumerate() {
            if let Some(key) = keys.get_key_by_index(section.key_slot) {
                validate_section_firmware_bounds(section).map_err(|e| {
                    let msg = e.to_string();
                    log_inferred_binary_base_hint(inferred_bin_base, &msg);
                    e
                })?;
                let firmware_data =
                    signed.image.read_bytes(section.start_addr, section.length as usize);
                let calculated_cmac = cmac_aes(&key, &firmware_data, section.key_size)
                    .map_err(|e| {
                        let msg = e.to_string();
                        log_inferred_binary_base_hint(inferred_bin_base, &msg);
                        e
                    })?;

                if i < signed.cmacs.len() {
                    let stored_cmac = signed.cmacs[i];
                    if calculated_cmac != stored_cmac {
                        problems.push(format!(
                            "section {}: CMAC mismatch (stored {:?}, calculated {:?})",
                            i, stored_cmac, calculated_cmac
                        ));
                    }
                } else {
                    problems.push(format!("section {}: no stored CMAC value", i));
                }
            } else {
                problems.push(format!(
                    "section {}: no key for key_slot {}",
                    i, section.key_slot
                ));
            }
        }
    }

    if !problems.is_empty() {
        log_inferred_binary_base_hint_for_verify_problems(inferred_bin_base, &problems);
        return Err(anyhow::anyhow!("verification failed:\n{}", problems.join("\n")));
    }

    info!("verify: {} — OK", input);

    Ok(())
}

pub fn cmd_keygen(
    input: Option<&str>,
    base: Option<&str>,
    output: Option<&str>,
) -> anyhow::Result<()> {
    let out_path = resolve_keygen_output_path(input, output)?;
    ensure_parent_dir_for_file(&out_path)?;

    if let Some(path) = input {
        let base_u32 = base.map(parse_hex_or_decimal).transpose()?;
        let (image, _) = load_image_with_bin_base(path, base_u32)?;
        let signed = verify_firmware(image, None).map_err(|e| {
            anyhow::anyhow!(
                "{:#}\n(hint: firmware must expose readable BVT/group/section config; encrypted blobs need plaintext section config in image, or fix --base for BIN)",
                e
            )
        })?;
        generate_key_file(&signed, &out_path)?;
    } else {
        SecureKeys::empty_template_32().write_to_file_pretty(&out_path)?;
    }

    info!("keygen: wrote {}", out_path.display());

    Ok(())
}

pub fn cmd_info(
    input: &str,
    keys_path: Option<&str>,
    base: Option<&str>,
) -> anyhow::Result<()> {
    let base_u32 = base
        .map(parse_hex_or_decimal)
        .transpose()?;
    let (image, bin_meta) = load_image_with_bin_base(input, base_u32)?;
    let inferred_bin_base = bin_meta.and_then(|(b, inferred)| inferred.then_some(b));

    let keys = if let Some(path) = keys_path {
        Some(SecureKeys::from_file(path)?)
    } else {
        None
    };

    let signed = verify_firmware(image, keys.as_ref()).map_err(|e| {
        let msg = e.to_string();
        log_inferred_binary_base_hint(inferred_bin_base, &msg);
        let need_keys_hint = keys_path.is_none()
            && msg.contains("need to provide key or plain text in image");
        if need_keys_hint {
            anyhow::anyhow!(
                "{:#} — provide keys JSON with `info -k` when section config is encrypted (group encrypt=true)",
                e
            )
        } else {
            e
        }
    })?;

    info!("\n=== BVT (Boot Vector Table) @ 0x{:08X} ===", signed.bvt_addr);
    info!(
        "  Image Vector Table Marker: 0x{:08X} ({})",
        signed.header.get_marker(),
        if signed.header.is_valid() { "Valid" } else { "Invalid" }
    );
    info!("  Boot Configuration Word: 0x{:08X}", signed.header.get_word());
    info!(
        "  Secure Boot Group Configuration Address: 0x{:08X}",
        signed.header.get_group_addr()
    );
    info!("  Application Start Address: 0x{:08X}", signed.header.get_app_addr());
    info!("  APP_WDG_TIMEOUT: {}", signed.header.get_app_wdg());

    info!("\n=== Secure Boot Group @ 0x{:08X} ===", signed.header.get_group_addr());
    info!(
        "  Configuration Group Marker: 0x{:08X} ({})",
        signed.group.get_marker(),
        if signed.group.is_valid() { "Valid" } else { "Invalid" }
    );
    info!("  Secure Boot Section Number: {}", signed.group.get_section_num());
    info!("  Encryption Flag: {}", signed.group.is_encrypt());
    info!("  AES Key Type/Size: {:?}", signed.group.get_key_size());
    info!("  Key Slot: {}", signed.group.get_key_slot());

    info!("\n=== Secure Boot Section ===");
    for (i, section) in signed.sections.iter().enumerate() {
        info!("  --------------------------------");
        info!("  Section {} @ 0x{:08X}", i, signed.group.get_section_addr(i));
        info!("  --------------------------------");
        info!(
            "  Configuration Section Marker: 0x{:04X} ({})",
            section.get_marker(),
            if section.is_valid() { "Valid" } else { "Invalid" }
        );
        info!("  AES Key Type/Size: {:?}", section.get_key_size());
        info!("  Key Slot: {}", section.get_key_slot());
        info!("  Section Start Address: 0x{:08X}", section.get_start_addr());
        info!("  Length: 0x{:08X}", section.get_length());
        info!("  CMAC Address: 0x{:08X}", section.get_cmac_addr());
        info!("  CMAC Result: {:02X?}", signed.get_cmac_at(i));
    }

    Ok(())
}

pub fn cmd_convert(
    input: &str,
    output: Option<&str>,
    format: Option<&str>,
    base: Option<&str>,
) -> anyhow::Result<()> {
    let base_addr = base
        .as_ref()
        .map(|b| parse_hex_or_decimal(b))
        .transpose()?;

    let image = load_image(input, base_addr)?;

    let (output_path, output_format) =
        resolve_output_path_and_format(input, output, format, "converted")?;
    ensure_parent_dir_for_file(&output_path)?;

    let bin_region = if output_format == "bin" {
        let bin_base = base_addr.unwrap_or_else(|| image.get_min_address().unwrap_or(0));
        let max_a = image.get_max_address().unwrap_or(0);
        if max_a < bin_base {
            return Err(anyhow::anyhow!(
                "cannot derive BIN size: max address 0x{:08X} < base 0x{:08X}",
                max_a,
                bin_base
            ));
        }
        let bin_size = (max_a - bin_base + 1) as usize;
        Some((bin_base, bin_size))
    } else {
        None
    };
    image.write_image_format(&output_path, &output_format, bin_region)?;

    info!(
        "convert: {} -> {} (format: {})",
        input,
        output_path.display(),
        output_format
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_format_from_path() {
        assert_eq!(infer_format_from_path("test.bin"), "bin");
        assert_eq!(infer_format_from_path("test.s19"), "s19");
        assert_eq!(infer_format_from_path("test.hex"), "hex");
    }
    #[test]
    fn test_format_to_extension() {
        assert_eq!(format_to_extension("bin"), "bin");
        assert_eq!(format_to_extension("s19"), "s19");
        assert_eq!(format_to_extension("hex"), "hex");
    }
    #[test]
    fn test_ensure_parent_dir_for_file() {
        let path = Path::new("test.bin");
        assert_eq!(ensure_parent_dir_for_file(path).unwrap(), ());
    }
    #[test]
    fn test_stem_from_input_path() {
        assert_eq!(stem_from_input_path("test.bin").unwrap(), "test");
    }
    #[test]
    fn test_output_path_means_directory() {
        assert_eq!(output_path_means_directory("target/test/"), true);
        assert_eq!(output_path_means_directory("images/unsigned.bin"), false);
    }
    #[test]
    fn test_resolve_output_format() {
        assert_eq!(resolve_output_format(None, "test.bin").unwrap(), "bin");
        assert_eq!(resolve_output_format(Some("bin"), "test.bin").unwrap(), "bin");
        assert_eq!(resolve_output_format(Some("s19"), "test.bin").unwrap(), "s19");
        assert_eq!(resolve_output_format(Some("hex"), "test.bin").unwrap(), "hex");
        assert_eq!(resolve_output_format(Some("bin"), "test.s19").unwrap(), "bin");
        assert_eq!(resolve_output_format(Some("s19"), "test.s19").unwrap(), "s19");
        assert_eq!(resolve_output_format(Some("hex"), "test.s19").unwrap(), "hex");
        assert_eq!(resolve_output_format(Some("bin"), "test.hex").unwrap(), "bin");
        assert_eq!(resolve_output_format(Some("s19"), "test.hex").unwrap(), "s19");
        assert_eq!(resolve_output_format(Some("hex"), "test.hex").unwrap(), "hex");
    }
    #[test]
    fn test_resolve_output_path_and_format() {
        let cwd = std::env::current_dir().unwrap();
        let (path, format) = resolve_output_path_and_format("test.bin", None, None, "test").unwrap();
        assert_eq!(path, cwd.join("test_test.bin"));
        assert_eq!(format, "bin");
        let (path, format) = resolve_output_path_and_format("test.bin", Some("test.bin"), None, "signed").unwrap();
        assert_eq!(path, PathBuf::from("test.bin"));
        assert_eq!(format, "bin");
        let (path, format) = resolve_output_path_and_format("test.bin", Some("test.s19"), None, "test").unwrap();
        assert_eq!(path, PathBuf::from("test.s19"));
        assert_eq!(format, "s19");
    }
    #[test]
    fn test_resolve_keygen_output_path() {
        let cwd = std::env::current_dir().unwrap();
        let path = resolve_keygen_output_path(None, None).unwrap();
        assert_eq!(path, cwd.join("keys.json"));
        let path = resolve_keygen_output_path(Some("images/unsigned.bin"), None).unwrap();
        assert_eq!(path, cwd.join("unsigned_keys.json"));
        let path = resolve_keygen_output_path(None, Some("none_keys.json")).unwrap();
        assert_eq!(path, PathBuf::from("none_keys.json"));
    }
    #[test]
    fn test_parse_hex_or_decimal() {
        assert_eq!(parse_hex_or_decimal("0x12345678").unwrap(), 0x12345678);
        assert_eq!(parse_hex_or_decimal("12345678").unwrap(), 12345678);
    }
    #[test]
    fn test_log_inferred_binary_base_hint() {
        log_inferred_binary_base_hint(None, "no key for key_slot");
        log_inferred_binary_base_hint(Some(0x4000), "no key for key_slot");
    }
    #[test]
    fn test_cmd_sign() {
        let keys = "config/sign_keys.json";
        cmd_sign("images/unsigned.bin", keys, Some("target/test/bin_signed.bin"), None, None, None, None).unwrap();
        assert!(Path::new("target/test/bin_signed.bin").exists());
        cmd_sign("images/unsigned.bin", keys, Some("target/test/bin_signed.hex"), None, None, None, None).unwrap();
        assert!(Path::new("target/test/bin_signed.hex").exists());
        cmd_sign("images/unsigned.bin", keys, Some("target/test/bin_signed.s19"), None, None, None, None).unwrap();
        assert!(Path::new("target/test/bin_signed.s19").exists());
        cmd_sign("images/unsigned.hex", keys, Some("target/test/hex_signed.bin"), None, None, None, None).unwrap();
        assert!(Path::new("target/test/hex_signed.bin").exists());
        cmd_sign("images/unsigned.hex", keys, Some("target/test/hex_signed.hex"), None, None, None, None).unwrap();
        assert!(Path::new("target/test/hex_signed.hex").exists());
        cmd_sign("images/unsigned.hex", keys, Some("target/test/hex_signed.s19"), None, None, None, None).unwrap();
        assert!(Path::new("target/test/hex_signed.s19").exists());
        cmd_sign("images/unsigned.s19", keys, Some("target/test/s19_signed.bin"), None, None, None, None).unwrap();
        assert!(Path::new("target/test/s19_signed.bin").exists());
        cmd_sign("images/unsigned.s19", keys, Some("target/test/s19_signed.hex"), None, None, None, None).unwrap();
        assert!(Path::new("target/test/s19_signed.hex").exists());
        cmd_sign("images/unsigned.s19", keys, Some("target/test/s19_signed.s19"), None, None, None, None).unwrap();
        assert!(Path::new("target/test/s19_signed.s19").exists());
    }
    #[test]
    fn test_cmd_convert_s19_s0_uses_output_path() {
        let out = Path::new("target/test/convert_s0_out.s19");
        let _ = std::fs::remove_file(out);
        cmd_convert(
            "images/unsigned.hex",
            Some("target/test/convert_s0_out.s19"),
            Some("s19"),
            None,
        )
        .unwrap();
        let text = std::fs::read_to_string(out).unwrap();
        let line0 = text.lines().next().unwrap().trim_end_matches('\r');
        assert!(line0.starts_with("S0"));
        let path_hex: String = out
            .to_string_lossy()
            .as_bytes()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        assert!(
            line0.contains(&path_hex),
            "S0 payload should hex-encode output path; got {line0:?}"
        );
    }
    #[test]
    fn test_cmd_verify() {
        let keys = "config/sign_keys.json";
        cmd_verify("images/signed.bin", Some(keys), None).unwrap();
        cmd_verify("images/signed.hex", Some(keys), None).unwrap();
        cmd_verify("images/signed.s19", Some(keys), None).unwrap();
    }
    #[test]
    fn test_cmd_keygen() {
        cmd_keygen(None, None, Some("target/test/none_keys.json")).unwrap();
        assert!(Path::new("target/test/none_keys.json").exists());
        cmd_keygen(Some("images/unsigned.bin"), None, Some("target/test/bin_keys.json")).unwrap();
        assert!(Path::new("target/test/bin_keys.json").exists());
        cmd_keygen(Some("images/unsigned.hex"), None, Some("target/test/hex_keys.json")).unwrap();
        assert!(Path::new("target/test/hex_keys.json").exists());
        cmd_keygen(Some("images/unsigned.s19"), None, Some("target/test/s19_keys.json")).unwrap();
        assert!(Path::new("target/test/s19_keys.json").exists());
    }
}