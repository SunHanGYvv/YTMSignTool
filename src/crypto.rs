use aes::cipher::{BlockDecrypt, BlockEncrypt, InvalidLength, KeyInit};
use aes::{Aes128, Aes192, Aes256};

use crate::types::SecureKeyLen;

const BLOCK_SIZE: usize = 16;

fn key_len_err(_: InvalidLength, key_len: SecureKeyLen) -> anyhow::Error {
    anyhow::anyhow!(
        "SecureKeyLen mismatch for {:?} (expected {} bytes)",
        key_len,
        key_len.key_size_bytes()
    )
}

fn xor_blocks(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

fn left_shift_one_bit(data: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    let mut overflow: u8 = 0;

    for i in (0..16).rev() {
        result[i] = data[i] << 1 | overflow;
        overflow = if data[i] & 0x80 != 0 { 1 } else { 0 };
    }

    result
}

fn generate_subkeys(key: &[u8], key_len: SecureKeyLen) -> anyhow::Result<([u8; 16], [u8; 16])> {
    let l = match key_len {
        SecureKeyLen::KeyLen128Bits => {
            let cipher = Aes128::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            let mut block = [0u8; 16];
            cipher.encrypt_block((&mut block).into());
            block
        }
        SecureKeyLen::KeyLen192Bits => {
            let cipher = Aes192::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            let mut block = [0u8; 16];
            cipher.encrypt_block((&mut block).into());
            block
        }
        SecureKeyLen::KeyLen256Bits => {
            let cipher = Aes256::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            let mut block = [0u8; 16];
            cipher.encrypt_block((&mut block).into());
            block
        }
    };

    let k1 = left_shift_one_bit(&l);
    let k1 = if l[0] & 0x80 != 0 {
        let mut k1 = k1;
        k1[15] ^= 0x87;
        k1
    } else {
        k1
    };

    let k2 = left_shift_one_bit(&k1);
    let k2 = if k1[0] & 0x80 != 0 {
        let mut k2 = k2;
        k2[15] ^= 0x87;
        k2
    } else {
        k2
    };

    Ok((k1, k2))
}

pub fn cmac_aes(key: &[u8], message: &[u8], key_len: SecureKeyLen) -> anyhow::Result<[u8; 16]> {
    let (k1, k2) = generate_subkeys(key, key_len)?;

    let mut blocks: Vec<[u8; 16]> = Vec::new();

    if message.is_empty() {
        let mut block = [0u8; 16];
        block[0] = 0x80;
        blocks.push(block);
    } else {
        let full_blocks = message.len() / BLOCK_SIZE;
        let has_partial = message.len() % BLOCK_SIZE != 0;

        for i in 0..full_blocks {
            let mut block = [0u8; 16];
            block.copy_from_slice(&message[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE]);
            blocks.push(block);
        }

        if has_partial {
            let remaining = &message[full_blocks * BLOCK_SIZE..];
            let mut block = [0u8; 16];
            block[..remaining.len()].copy_from_slice(remaining);
            block[remaining.len()] = 0x80;
            blocks.push(block);
        }
    }

    if blocks.is_empty() {
        let mut block = [0u8; 16];
        block[0] = 0x80;
        blocks.push(block);
    }

    let num_blocks = blocks.len();
    if num_blocks > 0 {
        let last_idx = num_blocks - 1;

        let is_complete = !message.is_empty() && message.len() % BLOCK_SIZE == 0;

        if is_complete {
            blocks[last_idx] = xor_blocks(&blocks[last_idx], &k1);
        } else {
            blocks[last_idx] = xor_blocks(&blocks[last_idx], &k2);
        }
    }

    let mut mac = [0u8; 16];

    match key_len {
        SecureKeyLen::KeyLen128Bits => {
            let cipher = Aes128::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            for block in &blocks {
                let xored = xor_blocks(&mac, block);
                let mut block = xored;
                cipher.encrypt_block((&mut block).into());
                mac = block;
            }
        }
        SecureKeyLen::KeyLen192Bits => {
            let cipher = Aes192::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            for block in &blocks {
                let xored = xor_blocks(&mac, block);
                let mut block = xored;
                cipher.encrypt_block((&mut block).into());
                mac = block;
            }
        }
        SecureKeyLen::KeyLen256Bits => {
            let cipher = Aes256::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            for block in &blocks {
                let xored = xor_blocks(&mac, block);
                let mut block = xored;
                cipher.encrypt_block((&mut block).into());
                mac = block;
            }
        }
    }

    Ok(mac)
}

pub fn encrypt_aes(key: &[u8], data: &[u8], key_len: SecureKeyLen) -> anyhow::Result<Vec<u8>> {
    let mut encrypted = Vec::with_capacity((data.len() + 15) / 16 * 16);

    match key_len {
        SecureKeyLen::KeyLen128Bits => {
            let cipher = Aes128::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            for chunk in data.chunks(16) {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                cipher.encrypt_block((&mut block).into());
                encrypted.extend_from_slice(&block);
            }
        }
        SecureKeyLen::KeyLen192Bits => {
            let cipher = Aes192::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            for chunk in data.chunks(16) {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                cipher.encrypt_block((&mut block).into());
                encrypted.extend_from_slice(&block);
            }
        }
        SecureKeyLen::KeyLen256Bits => {
            let cipher = Aes256::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            for chunk in data.chunks(16) {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                cipher.encrypt_block((&mut block).into());
                encrypted.extend_from_slice(&block);
            }
        }
    }

    Ok(encrypted)
}

pub fn decrypt_aes(key: &[u8], data: &[u8], key_len: SecureKeyLen) -> anyhow::Result<Vec<u8>> {
    if data.len() % BLOCK_SIZE != 0 {
        return Err(anyhow::anyhow!(
            "AES ciphertext length {} is not a multiple of {}",
            data.len(),
            BLOCK_SIZE
        ));
    }

    let mut decrypted = Vec::with_capacity(data.len());

    match key_len {
        SecureKeyLen::KeyLen128Bits => {
            let cipher = Aes128::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            for chunk in data.chunks(16) {
                let mut block = [0u8; 16];
                block.copy_from_slice(chunk);
                cipher.decrypt_block((&mut block).into());
                decrypted.extend_from_slice(&block);
            }
        }
        SecureKeyLen::KeyLen192Bits => {
            let cipher = Aes192::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            for chunk in data.chunks(16) {
                let mut block = [0u8; 16];
                block.copy_from_slice(chunk);
                cipher.decrypt_block((&mut block).into());
                decrypted.extend_from_slice(&block);
            }
        }
        SecureKeyLen::KeyLen256Bits => {
            let cipher = Aes256::new_from_slice(key).map_err(|e| key_len_err(e, key_len))?;
            for chunk in data.chunks(16) {
                let mut block = [0u8; 16];
                block.copy_from_slice(chunk);
                cipher.decrypt_block((&mut block).into());
                decrypted.extend_from_slice(&block);
            }
        }
    }

    Ok(decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmac_example_1() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let message = b"";
        let expected = hex::decode("bb1d6929e95937287fa37d129b756746").unwrap();

        let result = cmac_aes(&key, message, SecureKeyLen::KeyLen128Bits).unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_cmac_example_2() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let message = hex::decode("6bc1bee22e409f96e93d7e117393172a").unwrap();
        let expected = hex::decode("070a16b46b4d4144f79bdd9dd04a287c").unwrap();

        let result = cmac_aes(&key, &message, SecureKeyLen::KeyLen128Bits).unwrap();
        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_aes_encryption_decryption() {
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let plaintext = b"Hello, AES encryption!";

        let encrypted = encrypt_aes(&key, plaintext, SecureKeyLen::KeyLen128Bits).unwrap();
        let decrypted = decrypt_aes(&key, &encrypted, SecureKeyLen::KeyLen128Bits).unwrap();

        let decrypted = decrypted
            .into_iter()
            .take_while(|&b| b != 0)
            .collect::<Vec<_>>();

        assert_eq!(&decrypted[..], plaintext);
    }
}
