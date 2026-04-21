use std::path::Path;

use crate::crypto::encrypt_aes;
use crate::image::{load_image_with_bin_base, Image};
use crate::keys::SecureKeys;
use crate::types::SecureKeyLen;

pub const HCU_USER_MARKER: u32 = 0xA55A_A55A;

const KEYS_NUM: usize = 32;
const KEY_ROW_BYTES: usize = 32;
const PLAIN_LEN: usize = 64;
const CIPHER_SLOT_LEN: usize = 64;

const OFF_MARKER: usize = 0;
const OFF_KEY_SIZE: usize = 4;
const OFF_MAX_SLOT: usize = 4 + KEYS_NUM;
const OFF_KEYS: usize = OFF_MAX_SLOT + 4;
const OFF_PLAIN: usize = OFF_KEYS + KEYS_NUM * KEY_ROW_BYTES;
const OFF_CIPHER: usize = OFF_PLAIN + PLAIN_LEN;

pub const HCU_USER_KEYS_STRUCT_SIZE: usize = OFF_CIPHER + KEYS_NUM * CIPHER_SLOT_LEN;

pub fn find_hcu_user_keys_base(img: &Image) -> Option<u32> {
    const TYPICAL_BASE: u32 = 0x8400;
    if probe_hcu_user_keys(img, TYPICAL_BASE) {
        return Some(TYPICAL_BASE);
    }

    let min = *img.data.keys().next()?;
    let max = *img.data.keys().next_back()?;
    let last = max.saturating_sub(HCU_USER_KEYS_STRUCT_SIZE as u32);
    let mut addr = min;
    while addr <= last {
        if addr % 4 != 0 {
            addr = addr.wrapping_add(1);
            continue;
        }
        if probe_hcu_user_keys(img, addr) {
            return Some(addr);
        }
        addr = addr.wrapping_add(4);
    }
    None
}

fn probe_hcu_user_keys(img: &Image, base: u32) -> bool {
    let m = img.read_bytes(base.wrapping_add(OFF_MARKER as u32), 4);
    if u32::from_le_bytes(m.try_into().unwrap()) != HCU_USER_MARKER {
        return false;
    }
    let sizes = img.read_bytes(base.wrapping_add(OFF_KEY_SIZE as u32), KEYS_NUM);
    if !sizes.iter().all(|&b| b <= 2) {
        return false;
    }
    let ms = u32::from_le_bytes(
        img.read_bytes(base.wrapping_add(OFF_MAX_SLOT as u32), 4)
            .try_into()
            .unwrap(),
    );
    if ms >= KEYS_NUM as u32 {
        return false;
    }
    true
}

fn write_key_row(img: &mut Image, base: u32, slot: usize, key_bytes: &[u8]) {
    let row_addr = base.wrapping_add((OFF_KEYS + slot * KEY_ROW_BYTES) as u32);
    let mut row = [0xffu8; KEY_ROW_BYTES];
    row[..key_bytes.len()].copy_from_slice(key_bytes);
    img.write_bytes(row_addr, &row);
}

fn write_cipher_slot(img: &mut Image, base: u32, slot: usize, cipher_le: &[u8]) {
    debug_assert_eq!(cipher_le.len(), CIPHER_SLOT_LEN);
    let addr = base.wrapping_add((OFF_CIPHER + slot * CIPHER_SLOT_LEN) as u32);
    img.write_bytes(addr, cipher_le);
}

fn write_key_size_byte(img: &mut Image, base: u32, slot: usize, klen: SecureKeyLen) {
    let addr = base.wrapping_add((OFF_KEY_SIZE + slot) as u32);
    img.write_bytes(addr, &[klen as u8]);
}

pub fn patch_hcu_user_keys(img: &mut Image, keys: &SecureKeys) -> anyhow::Result<()> {
    let base = find_hcu_user_keys_base(img).ok_or_else(|| {
        anyhow::anyhow!(
            "no hcu_user_keys region found (expected magic {:#010X} and 32 key-size bytes 0..=2)",
            HCU_USER_MARKER
        )
    })?;

    let plain = img.read_bytes(base.wrapping_add(OFF_PLAIN as u32), PLAIN_LEN);

    if keys.get_max_key_slot().is_none() {
        anyhow::bail!(
            "prepare firmware: keys JSON has no non-empty entries to merge into hcu_user_keys"
        );
    }

    let mut any = false;
    let mut max_used_slot: u32 = 0;
    for slot in 0..KEYS_NUM {
        let Some(raw) = keys.get_key_by_index(slot as u8) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let klen = SecureKeyLen::from_key_byte_len(raw.len()).ok_or_else(|| {
            anyhow::anyhow!(
                "keys JSON index {}: key must be 16, 24, or 32 bytes when decoded from hex (got {} bytes)",
                slot,
                raw.len()
            )
        })?;
        any = true;
        max_used_slot = max_used_slot.max(slot as u32);

        write_key_size_byte(img, base, slot, klen);
        write_key_row(img, base, slot, &raw);

        let ct = encrypt_aes(&raw, &plain, klen)?;
        if ct.len() != PLAIN_LEN {
            anyhow::bail!("internal: AES-ECB output length {}", ct.len());
        }
        write_cipher_slot(img, base, slot, &ct);
    }

    if !any {
        anyhow::bail!(
            "prepare firmware: no valid non-empty key material could be merged (check hex encoding)"
        );
    }

    img.write_bytes(
        base.wrapping_add(OFF_MAX_SLOT as u32),
        &max_used_slot.to_le_bytes(),
    );

    Ok(())
}

pub const DEFAULT_PREPARE_TEMPLATE_HEX: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/images/prepare.hex"));

fn load_prepare_template(custom_template_file: Option<&Path>) -> anyhow::Result<Image> {
    match custom_template_file {
        None => Image::parse(DEFAULT_PREPARE_TEMPLATE_HEX),
        Some(path) => {
            let s = path.to_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "prepare template path is not valid UTF-8: {}",
                    path.display()
                )
            })?;
            let (img, _) = load_image_with_bin_base(s, None)?;
            Ok(img)
        }
    }
}

pub fn patch_prepare_firmware(
    keys: &SecureKeys,
    custom_template_file: Option<&Path>,
) -> anyhow::Result<Image> {
    let mut img = load_prepare_template(custom_template_file)?;
    patch_hcu_user_keys(&mut img, keys)?;
    Ok(img)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn find_prepare_hcu_region() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("images/prepare.hex");
        let text = std::fs::read_to_string(&p).unwrap();
        let img = Image::parse(&text).unwrap();
        let base = find_hcu_user_keys_base(&img).expect("hcu_user_keys");
        assert_eq!(base, 0x8400);
    }

    #[test]
    fn template_cipher_matches_ecb() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("images/prepare.hex");
        let text = std::fs::read_to_string(&p).unwrap();
        let img = Image::parse(&text).unwrap();
        let base = find_hcu_user_keys_base(&img).unwrap();
        let plain = img.read_bytes(base + OFF_PLAIN as u32, PLAIN_LEN);

        for slot in [0usize, 1, 2, 4] {
            let ks = img.read_bytes(base + (OFF_KEY_SIZE + slot) as u32, 1)[0];
            let klen = SecureKeyLen::from_u8(ks).unwrap();
            let row = img.read_bytes(
                base + (OFF_KEYS + slot * KEY_ROW_BYTES) as u32,
                KEY_ROW_BYTES,
            );
            let nbytes = klen.key_size_bytes();
            let key: Vec<u8> = row[..nbytes].to_vec();
            let exp = img.read_bytes(
                base + (OFF_CIPHER + slot * CIPHER_SLOT_LEN) as u32,
                CIPHER_SLOT_LEN,
            );
            let ct = encrypt_aes(&key, &plain, klen).unwrap();
            assert_eq!(ct, exp, "slot {}", slot);
        }
    }

    #[test]
    fn patch_overrides_template_key_size_from_json_length() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("images/prepare.hex");
        let text = std::fs::read_to_string(&p).unwrap();
        let img0 = Image::parse(&text).unwrap();
        let base = find_hcu_user_keys_base(&img0).unwrap();
        let slot = 3usize;
        let ks_before = img0.read_bytes(base + (OFF_KEY_SIZE + slot) as u32, 1)[0];
        let klen_before = SecureKeyLen::from_u8(ks_before).unwrap();
        assert_eq!(
            klen_before.key_size_bytes(),
            24,
            "fixture slot 3 is 192-bit"
        );

        let row_before = img0.read_bytes(
            base + (OFF_KEYS + slot * KEY_ROW_BYTES) as u32,
            KEY_ROW_BYTES,
        );
        let key16 = row_before[..16].to_vec();
        let keys = SecureKeys {
            keys: (0u8..=31u8)
                .map(|i| crate::keys::SecureKey {
                    index: i,
                    rindex: 31 - i,
                    data: if i == slot as u8 {
                        hex::encode(&key16)
                    } else {
                        String::new()
                    },
                })
                .collect(),
        };

        let mut img = img0.clone();
        patch_hcu_user_keys(&mut img, &keys).unwrap();
        let ks_after = img.read_bytes(base + (OFF_KEY_SIZE + slot) as u32, 1)[0];
        assert_eq!(ks_after, SecureKeyLen::KeyLen128Bits as u8);
        let plain = img.read_bytes(base + OFF_PLAIN as u32, PLAIN_LEN);
        let row = img.read_bytes(
            base + (OFF_KEYS + slot * KEY_ROW_BYTES) as u32,
            KEY_ROW_BYTES,
        );
        assert_eq!(&row[..16], key16.as_slice());
        let exp = img.read_bytes(
            base + (OFF_CIPHER + slot * CIPHER_SLOT_LEN) as u32,
            CIPHER_SLOT_LEN,
        );
        let ct = encrypt_aes(&key16, &plain, SecureKeyLen::KeyLen128Bits).unwrap();
        assert_eq!(ct, exp);
    }

    #[test]
    fn patch_roundtrip_unchanged_slot() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("images/prepare.hex");
        let text = std::fs::read_to_string(&p).unwrap();
        let img0 = Image::parse(&text).unwrap();
        let base = find_hcu_user_keys_base(&img0).unwrap();
        let row0 = img0.read_bytes(base + OFF_KEYS as u32, KEY_ROW_BYTES);

        let key_hex = hex::encode(&row0[..16]);
        let keys = SecureKeys {
            keys: (0u8..=31u8)
                .map(|i| crate::keys::SecureKey {
                    index: i,
                    rindex: 31 - i,
                    data: if i == 0 {
                        key_hex.clone()
                    } else {
                        String::new()
                    },
                })
                .collect(),
        };

        let mut img = img0.clone();
        patch_hcu_user_keys(&mut img, &keys).unwrap();
        let row_after = img.read_bytes(base + OFF_KEYS as u32, KEY_ROW_BYTES);
        assert_eq!(row0, row_after);
    }
}
