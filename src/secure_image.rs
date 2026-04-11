use std::collections::HashMap;

use rand::RngCore;

use crate::crypto::{cmac_aes, decrypt_aes, encrypt_aes};
use crate::image::Image;
use crate::keys::SecureKeys;
use crate::types::{SecureHeader, SecureKeyLen, SecureGroup, SecureSection};

pub const MAX_SECURE_BOOT_SECT_NUM: usize = 8;

pub const MAX_FIRMWARE_SECTION_BYTES: u32 = 32 * 1024 * 1024;

const BVT_HINT_ADDRS: &[u32] = &[0x0007_F800, 0x0007_F830, 0x0007_B800, 0x0200_0000, 0];

pub fn infer_binary_load_base(bytes: &[u8]) -> Option<u32> {
    let end = bytes.len().saturating_sub(48);
    for i in (0..=end).step_by(4) {
        if i + 4 > bytes.len() {
            break;
        }
        let m = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
        if m != SecureHeader::default_marker() {
            continue;
        }
        for &flash in BVT_HINT_ADDRS {
            if let Some(base) = flash.checked_sub(i as u32) {
                if base == 0 || (base & 0xFFF == 0) {
                    return Some(base);
                }
            }
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct SecureImage {
    pub image: Image,
    pub bvt_addr: u32,
    pub header: SecureHeader,
    pub group: SecureGroup,
    pub sections: Vec<SecureSection>,
    pub cmacs: Vec<[u8; 16]>,
}

impl SecureImage {
    pub fn new(image: Image) -> Self {
        Self {
            image,
            bvt_addr: 0,
            header: SecureHeader::default(),
            group: SecureGroup::default(),
            sections: Vec::new(),
            cmacs: Vec::new(),
        }
    }

    pub fn sign(&mut self, keys: &SecureKeys) -> anyhow::Result<()> {
        let (header, bvt_addr) = find_bvt_header(&self.image)?;
        self.header = header;
        self.bvt_addr = bvt_addr;

        let group = load_secure_boot_group(&self.image, &self.header)?;
        self.group = group;

        self.sections =
            load_secure_boot_sections(&self.image, &self.group, Some(keys))?;

        let mut sorted = self.sections.clone();
        sort_sections_by_cmac_addr_desc(&mut sorted);

        self.cmacs.clear();
        for section in &sorted {
            let key = keys
                .get_key_by_index(section.key_slot)
                .ok_or_else(|| anyhow::anyhow!("Key slot {} corresponding key", section.key_slot))?;

            if key.len() != section.key_size.key_size_bytes() {
                return Err(anyhow::anyhow!(
                    "Key length should be {} bytes (key_slot {})",
                    section.key_size.key_size_bytes(),
                    section.key_slot
                ));
            }

            validate_section_firmware_bounds(section)?;

            let firmware_data = self
                .image
                .read_bytes(section.start_addr, section.length as usize);
            let cmac = cmac_aes(&key, &firmware_data, section.key_size)?;
            self.cmacs.push(cmac);
        }

        self.write_to_flash(keys, &sorted)?;
        Ok(())
    }

    fn write_to_flash(
        &mut self,
        keys: &SecureKeys,
        sections_cmac_order: &[SecureSection],
    ) -> anyhow::Result<()> {
        let bvt_bytes = self.header.to_bytes();
        self.image.write_bytes(self.bvt_addr, &bvt_bytes);

        let sb_group_bytes = self.group.to_bytes();
        self.image
            .write_bytes(self.header.get_group_addr(), &sb_group_bytes);

        let n = self.group.get_section_num() as usize;
        for idx in 0..n {
            let section = &self.sections[idx];
            let mut section_bytes = section.to_bytes().to_vec();
            let section_addr = self.group.get_section_addr(idx);

            if self.group.is_encrypt() {
                let key = keys
                    .get_key_by_index(self.group.get_key_slot())
                    .ok_or_else(|| anyhow::anyhow!(
                        "Group encryption requires key for key_slot {}",
                        self.group.get_key_slot()
                    ))?;
                if key.len() != self.group.get_key_size().key_size_bytes() {
                    return Err(anyhow::anyhow!(
                        "Group key length should be {} bytes",
                        self.group.get_key_size().key_size_bytes()
                    ));
                }
                section_bytes = encrypt_aes(&key, &section_bytes, self.group.get_key_size())?;
            }

            self.image.write_bytes(section_addr, &section_bytes);
        }

        for (idx, cmac) in self.cmacs.iter().enumerate() {
            let cmac_addr = sections_cmac_order[idx].cmac_addr;
            self.image.write_bytes(cmac_addr, cmac);
        }

        Ok(())
    }

    pub fn write_firmware_format(
        &self,
        path: &std::path::Path,
        format: &str,
        bin_region: Option<(u32, usize)>,
    ) -> anyhow::Result<()> {
        self.image
            .write_image_format(path, format, bin_region)
    }

    pub fn sb_sections_cmac_order(&self) -> Vec<SecureSection> {
        let mut v = self.sections.clone();
        sort_sections_by_cmac_addr_desc(&mut v);
        v
    }

    #[allow(dead_code)]
    pub fn get_cmacs(&self) -> &[[u8; 16]] {
        &self.cmacs
    }

    pub fn get_cmac_at(&self, index: usize) -> &[u8; 16] {
        &self.cmacs[index]
    }
}

pub fn verify_firmware(
    image: Image,
    keys: Option<&SecureKeys>,
) -> anyhow::Result<SecureImage> {
    let (header, bvt_addr) = find_bvt_header(&image)?;
    let group = load_secure_boot_group(&image, &header)?;

    let sections = load_secure_boot_sections(&image, &group, keys)?;

    let mut sorted = sections.clone();
    sort_sections_by_cmac_addr_desc(&mut sorted);

    let mut cmacs = Vec::with_capacity(sorted.len());
    for section in &sorted {
        let mut cmac = [0u8; 16];
        let buf = image.read_bytes(section.cmac_addr, 16);
        cmac.copy_from_slice(&buf);
        cmacs.push(cmac);
    }

    Ok(SecureImage {
        image,
        header,
        group,
        sections: sections,
        cmacs,
        bvt_addr,
    })
}

pub fn sign_firmware(image: Image, keys: &SecureKeys) -> anyhow::Result<SecureImage> {
    let mut signed = SecureImage::new(image);
    signed.sign(keys)?;
    Ok(signed)
}

pub fn validate_section_firmware_bounds(section: &SecureSection) -> anyhow::Result<()> {
    if section.length > MAX_FIRMWARE_SECTION_BYTES {
        return Err(anyhow::anyhow!(
            "section length 0x{:08X} exceeds maximum 0x{:08X}",
            section.length,
            MAX_FIRMWARE_SECTION_BYTES
        ));
    }
    section
        .start_addr
        .checked_add(section.length)
        .ok_or_else(|| anyhow::anyhow!("section start_addr+length overflow"))?;
    Ok(())
}

fn merge_key_slot_requirement(
    m: &mut HashMap<u8, SecureKeyLen>,
    slot: u8,
    kl: SecureKeyLen,
) -> anyhow::Result<()> {
    if slot > 31 {
        return Err(anyhow::anyhow!("key_slot {} out of range 0..31", slot));
    }
    if let Some(prev) = m.get(&slot) {
        if *prev != kl {
            return Err(anyhow::anyhow!(
                "key_slot {} referenced with conflicting AES key sizes",
                slot
            ));
        }
        return Ok(());
    }
    m.insert(slot, kl);
    Ok(())
}

pub fn keys_config_from_signed_firmware(signed: &SecureImage) -> anyhow::Result<SecureKeys> {
    let mut need: HashMap<u8, SecureKeyLen> = HashMap::new();
    if signed.group.is_encrypt() {
        merge_key_slot_requirement(
            &mut need,
            signed.group.get_key_slot(),
            signed.group.get_key_size(),
        )?;
    }
    for s in &signed.sections {
        merge_key_slot_requirement(&mut need, s.key_slot, s.key_size)?;
    }

    let mut cfg = SecureKeys::empty_template_32();
    let mut rng = rand::thread_rng();
    for (slot, klen) in need {
        let n = klen.key_size_bytes();
        let mut raw = vec![0u8; n];
        rng.fill_bytes(&mut raw);
        cfg.keys[slot as usize].data = hex::encode_upper(raw);
    }
    Ok(cfg)
}

pub fn generate_key_file(
    signed: &SecureImage,
    path: impl AsRef<std::path::Path>,
) -> anyhow::Result<()> {
    keys_config_from_signed_firmware(signed)?.write_to_file_pretty(path)
}

fn dense_map_address_span(img: &Image) -> Option<(u32, u32)> {
    let min = *img.data.keys().next()?;
    let max = *img.data.keys().next_back()?;
    let span = max.saturating_sub(min).saturating_add(1) as u64;
    if span == 0 {
        return None;
    }
    let n = img.data.len() as u64;
    if n * 2 >= span {
        Some((min, max))
    } else {
        None
    }
}

fn find_bvt_header(img: &Image) -> anyhow::Result<(SecureHeader, u32)> {
    for &addr in BVT_HINT_ADDRS {
        if let Some(raw) = read_exact_48(img, addr) {
            if u32::from_le_bytes(raw[0..4].try_into().unwrap()) == SecureHeader::default_marker() {
                return Ok((SecureHeader::from_bytes(&raw)?, addr));
            }
        }
    }

    if let Some((min_a, max_a)) = dense_map_address_span(img) {
        for addr in (min_a..=max_a).step_by(4) {
            if let Some(raw) = read_exact_48(img, addr) {
                if u32::from_le_bytes(raw[0..4].try_into().unwrap()) == SecureHeader::default_marker() {
                    return Ok((SecureHeader::from_bytes(&raw)?, addr));
                }
            }
        }
    } else {
        for &addr in img.data.keys() {
            if addr % 4 != 0 {
                continue;
            }
            if let Some(raw) = read_exact_48(img, addr) {
                if u32::from_le_bytes(raw[0..4].try_into().unwrap()) == SecureHeader::default_marker() {
                    return Ok((SecureHeader::from_bytes(&raw)?, addr));
                }
            }
        }
    }

    Err(anyhow::anyhow!("No valid bvt_header_config_t (BVT magic number) found"))
}

fn read_exact_48(img: &Image, addr: u32) -> Option<[u8; 48]> {
    let mut buf = [0u8; 48];
    for i in 0..48u32 {
        buf[i as usize] = *img.data.get(&(addr + i))?;
    }
    Some(buf)
}

fn try_read_group_at(img: &Image, addr: u32) -> anyhow::Result<SecureGroup> {
    let head = img.read_bytes(addr, 8);
    let section_count = head[4];
    if section_count as usize > MAX_SECURE_BOOT_SECT_NUM {
        return Err(anyhow::anyhow!(
            "section_num {} exceeds MAX {}",
            section_count,
            MAX_SECURE_BOOT_SECT_NUM
        ));
    }
    let total = 8 + section_count as usize * 4;
    let buf = img.read_bytes(addr, total);
    SecureGroup::from_bytes(&buf, section_count)
}

fn load_secure_boot_group(img: &Image, header: &SecureHeader) -> anyhow::Result<SecureGroup> {
    let primary = header.get_group_addr();
    if let Ok(g) = try_read_group_at(img, primary) {
        if g.is_valid() {
            return Ok(g);
        }
    }

    let m = SecureGroup::default_marker().to_le_bytes();
    let group_magic_prefix_ok = |img: &Image, addr: u32| {
        img.data.get(&addr).copied() == Some(m[0])
            && img.data.get(&(addr + 1)).copied() == Some(m[1])
            && img.data.get(&(addr + 2)).copied() == Some(m[2])
            && img.data.get(&(addr + 3)).copied() == Some(m[3])
    };

    if let Some((min_a, max_a)) = dense_map_address_span(img) {
        for addr in (min_a..=max_a).step_by(4) {
            if !group_magic_prefix_ok(img, addr) {
                continue;
            }
            if let Ok(g) = try_read_group_at(img, addr) {
                if g.is_valid() {
                    return Ok(g);
                }
            }
        }
    } else {
        for &addr in img.data.keys() {
            if addr % 4 != 0 {
                continue;
            }
            if !group_magic_prefix_ok(img, addr) {
                continue;
            }
            if let Ok(g) = try_read_group_at(img, addr) {
                if g.is_valid() {
                    return Ok(g);
                }
            }
        }
    }

    Err(anyhow::anyhow!(
        "No valid group magic marker 0x{:08X} found", SecureGroup::default_marker()
    ))
}

fn load_secure_boot_sections(
    img: &Image,
    group: &SecureGroup,
    keys: Option<&SecureKeys>,
) -> anyhow::Result<Vec<SecureSection>> {
    let n = group.get_section_num() as usize;
    if n > MAX_SECURE_BOOT_SECT_NUM {
        return Err(anyhow::anyhow!("Invalid section count: {}", n));
    }

    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let section_addr = group.get_section_addr(i);
        let raw16 = img.read_bytes(section_addr, 16);
        if raw16.len() != 16 {
            return Err(anyhow::anyhow!("Section {} data length abnormal", i));
        }

        let parsed = resolve_section_config_blob(&raw16, group, keys, i)?;
        out.push(parsed);
    }

    Ok(out)
}

fn sort_sections_by_cmac_addr_desc(sections: &mut Vec<SecureSection>) {
    sections.sort_by(|a, b| b.cmac_addr.cmp(&a.cmac_addr));
}

fn section_blob_has_marker(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    u16::from_le_bytes([data[0], data[1]]) == SecureSection::default_marker()
}

fn resolve_section_config_blob(
    raw16: &[u8],
    group: &SecureGroup,
    keys: Option<&SecureKeys>,
    section_index: usize,
) -> anyhow::Result<SecureSection> {
    if !group.is_encrypt() {
        return SecureSection::from_bytes(raw16);
    }

    let Some(kc) = keys else {
        if section_blob_has_marker(raw16) {
            return SecureSection::from_bytes(raw16);
        }
        return Err(anyhow::anyhow!(
            "Group encrypt=true, section {} cannot be recognized (need to provide key or plain text in image)",
            section_index
        ));
    };

    let key = kc.get_key_by_index(group.get_key_slot()).ok_or_else(|| {
        anyhow::anyhow!(
            "Group encrypt=true, requires key for key_slot {}",
            group.get_key_slot()
        )
    })?;
    if key.len() != group.get_key_size().key_size_bytes() {
        return Err(anyhow::anyhow!(
            "Decryption key length should be {} bytes",
            group.get_key_size().key_size_bytes()
        ));
    }

    let dec = decrypt_aes(&key, raw16, group.get_key_size())?;
    if section_blob_has_marker(&dec) {
        return SecureSection::from_bytes(&dec);
    }
    if section_blob_has_marker(raw16) {
        return SecureSection::from_bytes(raw16);
    }

    SecureSection::from_bytes(&dec).or_else(|_| SecureSection::from_bytes(raw16))
}
