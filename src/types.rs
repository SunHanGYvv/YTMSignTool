pub const BVT_VALID_MARK: u32 = 0xA55A_A55A;

pub const SECURE_BOOT_GROUP_MARKER: u32 = 0xACBE_EFDD;

pub const SECURE_BOOT_SECTION_MARKER: u16 = 0x5AA5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SecureKeyLen {
    KeyLen128Bits = 0x00,
    KeyLen192Bits = 0x01,
    KeyLen256Bits = 0x02,
}

impl SecureKeyLen {
    pub fn key_size_bytes(self) -> usize {
        match self {
            Self::KeyLen128Bits => 16,
            Self::KeyLen192Bits => 24,
            Self::KeyLen256Bits => 32,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::KeyLen128Bits),
            0x01 => Some(Self::KeyLen192Bits),
            0x02 => Some(Self::KeyLen256Bits),
            _ => None,
        }
    }
}

impl Default for SecureKeyLen {
    fn default() -> Self {
        SecureKeyLen::KeyLen128Bits
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecureSection {
    pub marker: u16,
    pub key_size: SecureKeyLen,
    pub key_slot: u8,
    pub start_addr: u32,
    pub length: u32,
    pub cmac_addr: u32,
}

impl SecureSection {
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&self.marker.to_le_bytes());
        b[2] = self.key_size as u8;
        b[3] = self.key_slot;
        b[4..8].copy_from_slice(&self.start_addr.to_le_bytes());
        b[8..12].copy_from_slice(&self.length.to_le_bytes());
        b[12..16].copy_from_slice(&self.cmac_addr.to_le_bytes());
        b
    }

    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 16 {
            return Err(anyhow::anyhow!("SecureSection: data less than 16 bytes"));
        }
        let aes = SecureKeyLen::from_u8(data[2])
            .ok_or_else(|| anyhow::anyhow!("Invalid SecureKeyLen: 0x{:02X}", data[2]))?;
        Ok(Self {
            marker: u16::from_le_bytes([data[0], data[1]]),
            key_size: aes,
            key_slot: data[3],
            start_addr: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            length: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            cmac_addr: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        })
    }

    pub fn default_marker() -> u16 {
        SECURE_BOOT_SECTION_MARKER
    }

    pub fn is_valid(&self) -> bool {
        self.marker == SECURE_BOOT_SECTION_MARKER
    }

    pub fn get_marker(&self) -> u16 {
        self.marker
    }

    pub fn get_key_size(&self) -> SecureKeyLen {
        self.key_size
    }

    pub fn get_key_slot(&self) -> u8 {
        self.key_slot
    }

    pub fn get_start_addr(&self) -> u32 {
        self.start_addr
    }

    pub fn get_length(&self) -> u32 {
        self.length
    }

    pub fn get_cmac_addr(&self) -> u32 {
        self.cmac_addr
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecureGroup {
    marker: u32,
    section_num: u8,
    encrypt: bool,
    key_size: SecureKeyLen,
    key_slot: u8,
    section_addrs: Vec<u32>,
}

impl SecureGroup {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(8 + self.section_addrs.len() * 4);
        v.extend_from_slice(&self.marker.to_le_bytes());
        v.push(self.section_num);
        v.push(u8::from(self.encrypt));
        v.push(self.key_size as u8);
        v.push(self.key_slot);
        for a in &self.section_addrs {
            v.extend_from_slice(&a.to_le_bytes());
        }
        v
    }

    pub fn from_bytes(data: &[u8], section_count: u8) -> anyhow::Result<Self> {
        let need = 8usize + section_count as usize * 4;
        if data.len() < need {
            return Err(anyhow::anyhow!(
                "SecureGroup: needs at least {} bytes, actual {}",
                need,
                data.len()
            ));
        }
        let aes = SecureKeyLen::from_u8(data[6])
            .ok_or_else(|| anyhow::anyhow!("Invalid SecureKeyLen: 0x{:02X}", data[6]))?;
        let mut addrs = Vec::with_capacity(section_count as usize);
        for i in 0..section_count as usize {
            let o = 8 + i * 4;
            addrs.push(u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]));
        }
        Ok(Self {
            marker: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            section_num: data[4],
            encrypt: data[5] != 0,
            key_size: aes,
            key_slot: data[7],
            section_addrs: addrs,
        })
    }

    pub fn default_marker() -> u32 {
        SECURE_BOOT_GROUP_MARKER
    }

    pub fn is_valid(&self) -> bool {
        self.marker == SECURE_BOOT_GROUP_MARKER
    }

    pub fn is_encrypt(&self) -> bool {
        self.encrypt
    }

    pub fn get_marker(&self) -> u32 {
        self.marker
    }

    pub fn get_section_num(&self) -> u8 {
        self.section_num
    }

    pub fn get_key_size(&self) -> SecureKeyLen {
        self.key_size
    }

    pub fn get_key_slot(&self) -> u8 {
        self.key_slot
    }

    #[allow(dead_code)]
    pub fn get_section_addrs(&self) -> &[u32] {
        &self.section_addrs
    }

    pub fn get_section_addr(&self, index: usize) -> u32 {
        self.section_addrs[index]
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecureHeader {
    marker: u32,
    word: u32,
    group_addr: u32,
    reserved0: u32,
    app_addr: u32,
    reserved1: [u32; 5],
    app_wdg: u32,
}

impl SecureHeader {
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut b = [0u8; 48];
        b[0..4].copy_from_slice(&self.marker.to_le_bytes());
        b[4..8].copy_from_slice(&self.word.to_le_bytes());
        b[8..12].copy_from_slice(&self.group_addr.to_le_bytes());
        b[12..16].copy_from_slice(&self.reserved0.to_le_bytes());
        b[16..20].copy_from_slice(&self.app_addr.to_le_bytes());
        for (i, w) in self.reserved1.iter().enumerate() {
            b[20 + i * 4..24 + i * 4].copy_from_slice(&w.to_le_bytes());
        }
        b[40..44].copy_from_slice(&self.app_wdg.to_le_bytes());
        b
    }

    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        if data.len() < 48 {
            return Err(anyhow::anyhow!("SecureHeader: data less than 48 bytes"));
        }
        Ok(Self {
            marker: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            word: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            group_addr: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            reserved0: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            app_addr: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            reserved1: [
                u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
                u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
                u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
                u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
                u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            ],
            app_wdg: u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
        })
    }

    pub fn default_marker() -> u32 {
        BVT_VALID_MARK
    }

    pub fn is_valid(&self) -> bool {
        self.marker == BVT_VALID_MARK
    }

    pub fn get_marker(&self) -> u32 {
        self.marker
    }

    pub fn get_word(&self) -> u32 {
        self.word
    }

    pub fn get_group_addr(&self) -> u32 {
        self.group_addr
    }

    pub fn get_app_addr(&self) -> u32 {
        self.app_addr
    }

    pub fn get_app_wdg(&self) -> u32 {
        self.app_wdg
    }
}
