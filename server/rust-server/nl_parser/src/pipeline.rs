use aes::Aes128;
use anyhow::{Context, Result};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;

/// Client messages are small, but leave room for large local scripts/configs.
pub const MAX_WS_DECOMPRESSED_SIZE: usize = 64 * 1024 * 1024;
/// The embedded user module can legitimately be larger than a client message.
pub const MAX_MODULE_DECOMPRESSED_SIZE: usize = 256 * 1024 * 1024;

/// AES-128-CBC key (hex: 643831562A4B0F652559061470494A7D)
const KEY: [u8; 16] = [
    0x64, 0x38, 0x31, 0x56, 0x2A, 0x4B, 0x0F, 0x65, 0x25, 0x59, 0x06, 0x14, 0x70, 0x49, 0x4A,
    0x7D,
];

/// AES-128-CBC IV (ASCII: "5aAxpFpna5QqvYMv")
const IV: &[u8; 16] = b"5aAxpFpna5QqvYMv";

/// Decrypt AES-128-CBC with PKCS#7 padding.
pub fn decrypt(data: &[u8]) -> Result<Vec<u8>> {
    let mut buf = data.to_vec();
    let decryptor = Aes128CbcDec::new_from_slices(&KEY, IV)
        .map_err(|e| anyhow::anyhow!("cipher init failed: {e}"))?;
    let plaintext = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("decryption/unpadding failed: {e}"))?;
    Ok(plaintext.to_vec())
}

/// Encrypt AES-128-CBC with PKCS#7 padding.
pub fn encrypt(data: &[u8]) -> Result<Vec<u8>> {
    let encryptor = Aes128CbcEnc::new_from_slices(&KEY, IV)
        .map_err(|e| anyhow::anyhow!("cipher init failed: {e}"))?;
    // Allocate buffer: data + up to 16 bytes padding
    let block_size = 16;
    let padded_len = data.len() + (block_size - data.len() % block_size);
    let mut buf = vec![0u8; padded_len];
    buf[..data.len()].copy_from_slice(data);
    let ct = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
    Ok(ct.to_vec())
}

/// LZ4 block decompress. First 4 bytes are LE uncompressed size.
pub fn decompress(data: &[u8], max_output_size: usize) -> Result<Vec<u8>> {
    anyhow::ensure!(data.len() >= 4, "data too short for LZ4 header");
    let uncompressed_size = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    anyhow::ensure!(
        uncompressed_size <= max_output_size,
        "LZ4 output size {uncompressed_size} exceeds limit {max_output_size}"
    );
    let compressed = &data[4..];
    lz4_flex::block::decompress(compressed, uncompressed_size).context("LZ4 decompression failed")
}

/// LZ4 block compress with 4-byte LE uncompressed size header.
pub fn compress(data: &[u8]) -> Vec<u8> {
    let size_header = (data.len() as u32).to_le_bytes();
    let compressed = lz4_flex::block::compress(data);
    let mut out = Vec::with_capacity(4 + compressed.len());
    out.extend_from_slice(&size_header);
    out.extend_from_slice(&compressed);
    out
}

/// Full pipeline: decrypt then decompress module.bin bytes.
pub fn load_module(data: &[u8]) -> Result<Vec<u8>> {
    let decrypted = decrypt(data).context("decrypt stage")?;
    decompress(&decrypted, MAX_MODULE_DECOMPRESSED_SIZE).context("decompress stage")
}

/// Full pipeline: compress then encrypt decompressed FlatBuffer bytes.
pub fn save_module(data: &[u8]) -> Result<Vec<u8>> {
    let compressed = compress(data);
    encrypt(&compressed).context("encrypt stage")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compression_round_trip_respects_limit() {
        let input = b"patchwin.cc bounded LZ4 payload";
        let compressed = compress(input);
        let output = decompress(&compressed, input.len()).unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn oversized_header_is_rejected_before_decompression() {
        let claimed_size = 1025u32;
        let data = claimed_size.to_le_bytes();
        let error = decompress(&data, 1024).unwrap_err().to_string();
        assert!(error.contains("exceeds limit"));
    }

    #[test]
    fn truncated_header_is_rejected() {
        let error = decompress(&[0, 1, 2], 1024).unwrap_err().to_string();
        assert!(error.contains("too short"));
    }
}
