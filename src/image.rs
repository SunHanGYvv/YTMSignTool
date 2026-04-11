use std::collections::BTreeMap;
use std::path::Path;

use ihex::Record as IhexRecord;
use srec::{
    reader::read_records, writer::generate_srec_file, Address16, Address24, Address32, Data,
    Record as SrecRecord,
};

const IHEX_MAX_CHUNK: usize = 16;
const SREC_MAX_CHUNK: usize = 16;

const DENSE_EXPORT_MIN_FF_RUN: usize = 16;
const BIN_DEFAULT_ERASE_BYTE: u8 = 0xFF;
const SREC_S0_MAX_TEXT: usize = 240;

fn clamp_s0_header(s: &str) -> String {
    if s.len() <= SREC_S0_MAX_TEXT {
        return s.to_string();
    }
    let mut t = s[..SREC_S0_MAX_TEXT].to_string();
    while !t.is_char_boundary(t.len()) {
        t.pop();
    }
    t
}

fn is_dense_consecutive_map(data: &BTreeMap<u32, u8>) -> bool {
    if data.len() < 2 {
        return false;
    }
    let min = *data.keys().next().unwrap();
    let max = *data.keys().next_back().unwrap();
    let span = (max - min) as usize + 1;
    if span != data.len() {
        return false;
    }
    data.iter()
        .enumerate()
        .all(|(i, (a, _))| *a == min.wrapping_add(i as u32))
}

fn dense_map_to_export_segments(data: &BTreeMap<u32, u8>) -> Vec<(u32, Vec<u8>)> {
    let min = *data.keys().next().unwrap();
    let v: Vec<u8> = (0..data.len())
        .map(|j| data[&min.wrapping_add(j as u32)])
        .collect();
    let mut out = Vec::new();
    let mut piece_start = 0usize;
    let mut i = 0usize;
    while i < v.len() {
        if v[i] != BIN_DEFAULT_ERASE_BYTE {
            i += 1;
            continue;
        }
        let gap_start = i;
        while i < v.len() && v[i] == BIN_DEFAULT_ERASE_BYTE {
            i += 1;
        }
        let gap_len = i - gap_start;
        if gap_len >= DENSE_EXPORT_MIN_FF_RUN {
            if gap_start > piece_start {
                out.push((
                    min.wrapping_add(piece_start as u32),
                    v[piece_start..gap_start].to_vec(),
                ));
            }
            piece_start = i;
        }
    }
    if piece_start < v.len() {
        out.push((
            min.wrapping_add(piece_start as u32),
            v[piece_start..].to_vec(),
        ));
    }
    out
}

fn chunk_at_max(start: u32, bytes: &[u8], max_payload: usize) -> Vec<(u32, Vec<u8>)> {
    let mut r = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let n = (bytes.len() - off).min(max_payload);
        r.push((
            start.wrapping_add(off as u32),
            bytes[off..off + n].to_vec(),
        ));
        off += n;
    }
    r
}

fn export_payload_chunks(data: &BTreeMap<u32, u8>, max_payload: usize) -> Vec<(u32, Vec<u8>)> {
    if is_dense_consecutive_map(data) {
        let mut chunks = Vec::new();
        for (seg_start, seg) in dense_map_to_export_segments(data) {
            chunks.extend(chunk_at_max(seg_start, &seg, max_payload));
        }
        chunks
    } else {
        consecutive_payload_chunks(data, max_payload)
    }
}

fn consecutive_payload_chunks(data: &BTreeMap<u32, u8>, max_payload: usize) -> Vec<(u32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut cur_start: Option<u32> = None;
    let mut cur_data: Vec<u8> = Vec::new();

    for (&addr, &byte) in data {
        if let Some(start) = cur_start {
            if addr == start + cur_data.len() as u32 && cur_data.len() < max_payload {
                cur_data.push(byte);
            } else {
                if !cur_data.is_empty() {
                    out.push((start, std::mem::take(&mut cur_data)));
                }
                cur_start = Some(addr);
                cur_data.push(byte);
            }
        } else {
            cur_start = Some(addr);
            cur_data.push(byte);
        }
    }
    if !cur_data.is_empty() {
        out.push((cur_start.unwrap(), cur_data));
    }
    out
}

fn insert_at(map: &mut BTreeMap<u32, u8>, addr: u32, bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        map.insert(addr + i as u32, *b);
    }
}

fn ihex_build_records(data: &BTreeMap<u32, u8>) -> Vec<IhexRecord> {
    let chunks = export_payload_chunks(data, IHEX_MAX_CHUNK);
    let mut records = Vec::new();
    let mut cur_hi: Option<u16> = None;
    for (addr, value) in chunks {
        let hi = (addr >> 16) as u16;
        if cur_hi != Some(hi) {
            records.push(IhexRecord::ExtendedLinearAddress(hi));
            cur_hi = Some(hi);
        }
        records.push(IhexRecord::Data {
            offset: (addr & 0xFFFF) as u16,
            value,
        });
    }
    records.push(IhexRecord::EndOfFile);
    records
}

fn srec_build_records(
    data: &BTreeMap<u32, u8>,
    entry: Option<u32>,
    s0_header: Option<&str>,
) -> Vec<SrecRecord> {
    let max_a = data.keys().next_back().copied().unwrap_or(0);
    let ep = entry.unwrap_or(0);
    let need = max_a.max(ep);
    let kind = if max_a > 0xFFFFFF {
        3u8
    } else if max_a > 0xFFFF {
        2u8
    } else {
        1u8
    };
    let chunks = export_payload_chunks(data, SREC_MAX_CHUNK);
    let mut out: Vec<SrecRecord> = Vec::with_capacity(chunks.len() + 1 + usize::from(s0_header.is_some()));
    if let Some(h) = s0_header {
        out.push(SrecRecord::S0(clamp_s0_header(h)));
    }
    out.extend(chunks.into_iter().map(|(addr, payload)| match kind {
        3 => SrecRecord::S3(Data {
            address: Address32(addr),
            data: payload,
        }),
        2 => SrecRecord::S2(Data {
            address: Address24(addr),
            data: payload,
        }),
        _ => SrecRecord::S1(Data {
            address: Address16(addr as u16),
            data: payload,
        }),
    }));
    out.push(if need > 0xFFFFFF {
        SrecRecord::S7(Address32(ep))
    } else if need > 0xFFFF {
        SrecRecord::S8(Address24(ep))
    } else {
        SrecRecord::S9(Address16(ep as u16))
    });
    out
}

#[derive(Debug, Clone)]
pub struct Image {
    pub data: BTreeMap<u32, u8>,
    #[allow(dead_code)]
    pub base_address: u32,
    #[allow(dead_code)]
    pub entry_point: Option<u32>,
}

impl Image {
    pub fn parse(content: &str) -> anyhow::Result<Self> {
        let mut data = BTreeMap::new();
        let mut extended_address: u32 = 0;
        let mut entry_point: Option<u32> = None;
        let mut base_address: Option<u32> = None;
        let mut reader = ihex::Reader::new(content);
        while let Some(item) = reader.next() {
            let rec = item.map_err(|e| anyhow::anyhow!("Intel HEX: {}", e))?;
            match rec {
                IhexRecord::Data { offset, value } => {
                    let addr = extended_address.wrapping_add(offset as u32);
                    if base_address.is_none() {
                        base_address = Some(addr);
                    }
                    insert_at(&mut data, addr, &value);
                }
                IhexRecord::EndOfFile => break,
                IhexRecord::ExtendedSegmentAddress(seg) => {
                    extended_address = (seg as u32) << 4;
                }
                IhexRecord::StartSegmentAddress { cs, ip } => {
                    entry_point = Some(((cs as u32) << 4) + (ip as u32));
                }
                IhexRecord::ExtendedLinearAddress(hi) => {
                    extended_address = (hi as u32) << 16;
                }
                IhexRecord::StartLinearAddress(addr) => {
                    entry_point = Some(addr);
                }
            }
        }

        Ok(Self {
            data,
            base_address: base_address.unwrap_or(0),
            entry_point,
        })
    }

    pub fn get_min_address(&self) -> Option<u32> {
        self.data.keys().next().copied()
    }

    pub fn get_max_address(&self) -> Option<u32> {
        self.data.keys().next_back().copied()
    }

    pub fn read_bytes(&self, address: u32, length: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(length);
        for i in 0..length {
            if let Some(&byte) = self.data.get(&(address + i as u32)) {
                result.push(byte);
            } else {
                result.push(0xFF);
            }
        }
        result
    }

    pub fn write_bytes(&mut self, address: u32, data: &[u8]) {
        for (i, byte) in data.iter().enumerate() {
            self.data.insert(address + i as u32, *byte);
        }
    }

    pub fn to_binary_with_base(&self, base_address: u32, size: usize, fill_byte: u8) -> Vec<u8> {
        let mut binary = vec![fill_byte; size];
        for (&addr, &byte) in &self.data {
            if addr >= base_address && addr < base_address + size as u32 {
                binary[(addr - base_address) as usize] = byte;
            }
        }
        binary
    }

    pub fn write_image_format(
        &self,
        path: &Path,
        format: &str,
        bin_region: Option<(u32, usize)>,
    ) -> anyhow::Result<()> {
        match format {
            "hex" => std::fs::write(path, self.to_hex())?,
            "s19" => {
                let s0 = path.to_string_lossy();
                let records = srec_build_records(
                    &self.data,
                    self.entry_point,
                    Some(s0.as_ref()),
                );
                std::fs::write(
                    path,
                    generate_srec_file(&records).replace('\n', "\r\n"),
                )?;
            }
            "bin" => {
                let (base, size) = bin_region.ok_or_else(|| {
                    anyhow::anyhow!("internal error: BIN output requires base and size")
                })?;
                std::fs::write(path, self.to_binary_with_base(base, size, 0xFF))?;
            }
            _ => return Err(anyhow::anyhow!("Unsupported output format: {}", format)),
        }
        Ok(())
    }

    pub fn to_hex(&self) -> String {
        let records = ihex_build_records(&self.data);
        ihex::create_object_file_representation(&records).expect("ihex serialize")
    }

    #[allow(dead_code)]
    pub fn to_s19(&self) -> String {
        let records = srec_build_records(&self.data, self.entry_point, None);
        generate_srec_file(&records).replace('\n', "\r\n")
    }

    pub fn parse_s19(content: &str) -> anyhow::Result<Self> {
        let mut data = BTreeMap::new();
        let mut entry_point: Option<u32> = None;

        for item in read_records(content) {
            let r = item.map_err(|e| anyhow::anyhow!("S-record: {}", e))?;
            match r {
                SrecRecord::S0(_) => {}
                SrecRecord::S1(d) => insert_at(&mut data, d.address.0 as u32, &d.data),
                SrecRecord::S2(d) => insert_at(&mut data, d.address.into(), &d.data),
                SrecRecord::S3(d) => insert_at(&mut data, d.address.into(), &d.data),
                SrecRecord::S7(a) => entry_point = Some(a.into()),
                SrecRecord::S8(a) => entry_point = Some(a.into()),
                SrecRecord::S9(a) => entry_point = Some(a.0 as u32),
                _ => {}
            }
        }

        let base_address = data.keys().next().copied().unwrap_or(0);
        Ok(Self {
            data,
            base_address,
            entry_point,
        })
    }
}

pub fn load_image_with_bin_base(
    path: &str,
    base_address: Option<u32>,
) -> anyhow::Result<(Image, Option<(u32, bool)>)> {
    let bytes = std::fs::read(path)?;

    if !bytes.is_empty() {
        if bytes[0] == b':' {
            let content = String::from_utf8(bytes)?;
            return Ok((Image::parse(&content)?, None));
        }

        if bytes[0] == b'S' {
            let content = String::from_utf8(bytes)?;
            return Ok((Image::parse_s19(&content)?, None));
        }
    }

    let (base, inferred) = match base_address {
        Some(b) => (b, false),
        None => match crate::secure_image::infer_binary_load_base(&bytes) {
            Some(b) => (b, true),
            None => (0, false),
        },
    };

    let mut image = Image {
        data: BTreeMap::new(),
        base_address: base,
        entry_point: None,
    };

    for (i, byte) in bytes.iter().enumerate() {
        image.data.insert(base.wrapping_add(i as u32), *byte);
    }

    Ok((image, Some((base, inferred))))
}

pub fn load_image(path: &str, base_address: Option<u32>) -> anyhow::Result<Image> {
    Ok(load_image_with_bin_base(path, base_address)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dense_bin_export_payload_is_sparse_not_full_size() {
        let hex_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("images/unsigned.hex");
        let content = std::fs::read_to_string(&hex_path).expect("unsigned.hex");
        let h = Image::parse(&content).expect("parse hex");
        let bin_base = h.get_min_address().expect("min");
        let max_a = h.get_max_address().expect("max");
        let size = (max_a - bin_base + 1) as usize;
        let bin = h.to_binary_with_base(bin_base, size, 0xFF);
        let mut data = BTreeMap::new();
        for (i, b) in bin.iter().enumerate() {
            data.insert(bin_base.wrapping_add(i as u32), *b);
        }
        assert!(
            is_dense_consecutive_map(&data),
            "expected dense map from contiguous bin"
        );
        let chunks = export_payload_chunks(&data, SREC_MAX_CHUNK);
        let total_payload: usize = chunks.iter().map(|(_, d)| d.len()).sum();
        assert!(
            total_payload < 100_000,
            "expected sparse export (~22k bytes), got {} bytes in {} chunks",
            total_payload,
            chunks.len()
        );

        let hf = Image {
            data,
            base_address: bin_base,
            entry_point: None,
        };
        let s19 = hf.to_s19();
        assert!(
            s19.len() < 200_000,
            "to_s19() should stay compact for dense bin, got {} bytes",
            s19.len()
        );
    }

    #[test]
    fn to_s19_in_memory_has_no_s0() {
        let hex_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("images/unsigned.hex");
        let hf = Image::parse(&std::fs::read_to_string(&hex_path).unwrap()).unwrap();
        let s19 = hf.to_s19();
        let first = s19.lines().next().expect("line");
        assert!(
            !first.starts_with("S0"),
            "to_s19() should omit S0; first line: {first:?}"
        );
    }

    #[test]
    fn write_image_format_s19_prefixes_s0_with_output_path() {
        let hex_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("images/unsigned.hex");
        let hf = Image::parse(&std::fs::read_to_string(&hex_path).unwrap()).unwrap();
        let out = std::env::temp_dir().join("ytm_write_s19_s0_test.s19");
        let _ = std::fs::remove_file(&out);
        hf.write_image_format(&out, "s19", None).unwrap();
        let text = std::fs::read_to_string(&out).unwrap();
        let line0 = text.lines().next().unwrap().trim_end_matches('\r');
        assert!(line0.starts_with("S0"), "file output should start with S0: {line0:?}");
        let path_hex: String = out
            .to_string_lossy()
            .as_bytes()
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        assert!(line0.contains(&path_hex), "S0 should encode output path: {line0:?}");
    }

    #[test]
    fn roundtrip_write_bin_reload_to_s19_is_compact() {
        let hex_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("images/unsigned.hex");
        let hf = Image::parse(&std::fs::read_to_string(&hex_path).unwrap()).unwrap();
        let bin_base = hf.get_min_address().unwrap();
        let max_a = hf.get_max_address().unwrap();
        let bin_size = (max_a - bin_base + 1) as usize;
        let bin_path = std::env::temp_dir().join("ytm_roundtrip_unsigned.bin");
        let _ = std::fs::remove_file(&bin_path);
        hf.write_image_format(&bin_path, "bin", Some((bin_base, bin_size)))
            .unwrap();

        let hf2 = load_image(bin_path.to_str().unwrap(), Some(bin_base)).unwrap();
        assert_eq!(hf2.data.len(), bin_size);
        assert!(
            is_dense_consecutive_map(&hf2.data),
            "reloaded bin map should be dense consecutive"
        );
        let s19 = hf2.to_s19();
        assert!(
            s19.len() < 200_000,
            "roundtrip s19 len {} (lines {})",
            s19.len(),
            s19.lines().count()
        );
    }
}
