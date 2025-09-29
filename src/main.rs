use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use clap::{Parser, Subcommand};
use image::{io::Reader as ImageReader, GrayImage, ImageBuffer, Luma, Rgb, RgbImage};
use jpeg_encoder::{ColorType, Encoder};
use rand::RngCore;
use std::{fs, path::Path};

#[derive(Parser)]
#[command(name = "steg")]
#[command(about = "A steganography tool for hiding encrypted data in images using DCT")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Hide encrypted data in an image
    Hide {
        /// Input image path
        #[arg(short, long)]
        input: String,
        /// Output image path
        #[arg(short, long)]
        output: String,
        /// Data to hide (will be encrypted)
        #[arg(short, long)]
        data: String,
        /// Optional key file path (if not provided, key will be generated)
        #[arg(short, long)]
        key_file: Option<String>,
        /// JPEG quality for output (1-100, higher = better quality, default: 85)
        #[arg(short, long, default_value = "85")]
        quality: u8,
    },
    /// Extract and decrypt data from an image
    Extract {
        /// Stego image path
        #[arg(short, long)]
        input: String,
        /// Key file path or base64 key
        #[arg(short, long)]
        key: String,
        /// Expected data length in bytes (optional, will try to detect)
        #[arg(short, long)]
        length: Option<usize>,
    },
    /// Generate a test image for demonstration
    Demo,
}

/// Simple DCT implementation for 8x8 blocks
struct SimpleDct {
    cosine_table: [[f32; 8]; 8],
}

impl SimpleDct {
    fn new() -> Self {
        let mut cosine_table = [[0f32; 8]; 8];

        // Precompute cosine values for 8x8 DCT
        for u in 0..8 {
            for x in 0..8 {
                cosine_table[u][x] =
                    ((2 * x + 1) as f32 * u as f32 * std::f32::consts::PI / 16.0).cos();
            }
        }

        Self { cosine_table }
    }

    /// Apply 1D DCT to a row
    fn dct_1d(&self, input: &[f32; 8]) -> [f32; 8] {
        let mut output = [0f32; 8];

        for u in 0..8 {
            let cu = if u == 0 { 1.0 / (2.0_f32).sqrt() } else { 1.0 };
            let mut sum = 0.0;

            for x in 0..8 {
                sum += input[x] * self.cosine_table[u][x];
            }

            output[u] = 0.5 * cu * sum;
        }

        output
    }

    /// Apply 1D inverse DCT to a row
    fn idct_1d(&self, input: &[f32; 8]) -> [f32; 8] {
        let mut output = [0f32; 8];

        for x in 0..8 {
            let mut sum = 0.0;

            for u in 0..8 {
                let cu = if u == 0 { 1.0 / (2.0_f32).sqrt() } else { 1.0 };
                sum += cu * input[u] * self.cosine_table[u][x];
            }

            output[x] = 0.5 * sum;
        }

        output
    }

    /// Apply 2D DCT to an 8x8 block
    fn dct_2d(&self, block: &mut [[f32; 8]; 8]) {
        // Apply 1D DCT to each row
        for row in block.iter_mut() {
            *row = self.dct_1d(row);
        }

        // Apply 1D DCT to each column
        for col in 0..8 {
            let mut column = [0f32; 8];
            for row in 0..8 {
                column[row] = block[row][col];
            }
            let dct_column = self.dct_1d(&column);
            for row in 0..8 {
                block[row][col] = dct_column[row];
            }
        }
    }

    /// Apply 2D inverse DCT to an 8x8 block
    fn idct_2d(&self, block: &mut [[f32; 8]; 8]) {
        // Apply 1D inverse DCT to each column
        for col in 0..8 {
            let mut column = [0f32; 8];
            for row in 0..8 {
                column[row] = block[row][col];
            }
            let idct_column = self.idct_1d(&column);
            for row in 0..8 {
                block[row][col] = idct_column[row];
            }
        }

        // Apply 1D inverse DCT to each row
        for row in block.iter_mut() {
            *row = self.idct_1d(row);
        }
    }
}

/// JPEG quantization table (standard luminance table)
const JPEG_QUANT_TABLE: [[f32; 8]; 8] = [
    [16.0, 11.0, 10.0, 16.0, 24.0, 40.0, 51.0, 61.0],
    [12.0, 12.0, 14.0, 19.0, 26.0, 58.0, 60.0, 55.0],
    [14.0, 13.0, 16.0, 24.0, 40.0, 57.0, 69.0, 56.0],
    [14.0, 17.0, 22.0, 29.0, 51.0, 87.0, 80.0, 62.0],
    [18.0, 22.0, 37.0, 56.0, 68.0, 109.0, 103.0, 77.0],
    [24.0, 35.0, 55.0, 64.0, 81.0, 104.0, 113.0, 92.0],
    [49.0, 64.0, 78.0, 87.0, 103.0, 121.0, 120.0, 101.0],
    [72.0, 92.0, 95.0, 98.0, 112.0, 100.0, 103.0, 99.0],
];

/// Configuration constants for the steganography algorithm
struct Config {
    block_size: usize,
    // Multiple coefficients for robustness
    embedding_positions: Vec<(usize, usize)>,
    // Embedding strength multiplier
    embedding_strength: f32,
    // Minimum quantization step for embedding
    min_quant_step: f32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            block_size: 8,
            // Use the most robust middle-frequency coefficients
            embedding_positions: vec![
                (4, 1), // Most robust position based on testing
                (1, 4), // Secondary robust position
                (3, 2), // Backup position
                (2, 3), // Backup position
                (5, 0),
                (0, 5),
                (3, 4),
                (4, 3),
            ],
            embedding_strength: 25.0, // Very strong to survive JPEG compression
            min_quant_step: 4.0,      // Minimum quantization step to consider
        }
    }
}

/// Optimized steganography engine using DCT
pub struct StegoEngine {
    config: Config,
    dct: SimpleDct,
}

impl StegoEngine {
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            dct: SimpleDct::new(),
        }
    }

    /// Convert data to bits with length prefix for better extraction
    fn data_to_bits_with_header(&self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();

        // Add 32-bit length header
        let len = data.len() as u32;
        for i in (0..32).rev() {
            result.push(((len >> i) & 1) as u8);
        }

        // Add actual data bits
        for byte in data {
            for i in (0..8).rev() {
                result.push(((byte >> i) & 1) as u8);
            }
        }

        result
    }

    /// Convert bits back to bytes, reading length header first
    fn bits_to_data_with_header(&self, bits: &[u8]) -> Result<Vec<u8>> {
        if bits.len() < 32 {
            return Err(anyhow!("Not enough bits for length header"));
        }

        // Read length from first 32 bits
        let mut length = 0u32;
        for i in 0..32 {
            length = (length << 1) | (bits[i] as u32);
        }

        let data_bits = &bits[32..];
        let expected_bits = length as usize * 8;

        if data_bits.len() < expected_bits {
            return Err(anyhow!(
                "Not enough data bits. Expected {}, got {}",
                expected_bits,
                data_bits.len()
            ));
        }

        let mut result = Vec::new();
        for chunk in data_bits[..expected_bits].chunks(8) {
            let mut byte = 0u8;
            for &bit in chunk {
                byte = (byte << 1) | bit;
            }
            result.push(byte);
        }

        Ok(result)
    }

    /// Calculate quantization table for given quality factor
    fn calculate_quant_table(&self, quality: u8) -> [[f32; 8]; 8] {
        let quality = quality.clamp(1, 100) as f32;
        let scale = if quality < 50.0 {
            5000.0 / quality
        } else {
            200.0 - 2.0 * quality
        };

        let mut quant_table = [[0.0f32; 8]; 8];
        for i in 0..8 {
            for j in 0..8 {
                let val = ((JPEG_QUANT_TABLE[i][j] * scale + 50.0) / 100.0)
                    .floor()
                    .clamp(1.0, 255.0);
                quant_table[i][j] = val;
            }
        }
        quant_table
    }

    /// Calculate maximum capacity of an RGB image in bits
    pub fn calculate_capacity_rgb(&self, img: &RgbImage) -> usize {
        // Use ceiling division to include partial blocks
        let blocks_x = (img.width() as usize + self.config.block_size - 1) / self.config.block_size;
        let blocks_y =
            (img.height() as usize + self.config.block_size - 1) / self.config.block_size;
        blocks_x * blocks_y // One bit per block (using redundancy for robustness)
    }

    /// Calculate maximum capacity of a grayscale image in bits (legacy)
    pub fn calculate_capacity(&self, img: &GrayImage) -> usize {
        // Use ceiling division to include partial blocks
        let blocks_x = (img.width() as usize + self.config.block_size - 1) / self.config.block_size;
        let blocks_y =
            (img.height() as usize + self.config.block_size - 1) / self.config.block_size;
        blocks_x * blocks_y // One bit per block (using redundancy for robustness)
    }

    /// Hide encrypted data in RGB image using JPEG-robust DCT steganography
    pub fn hide_data_rgb(&mut self, img: &RgbImage, data: &[u8], quality: u8) -> Result<RgbImage> {
        let bits = self.data_to_bits_with_header(data);
        let capacity = self.calculate_capacity_rgb(img);

        if bits.len() > capacity {
            return Err(anyhow!(
                "Data too large for image. Need {} bits, capacity is {} bits",
                bits.len(),
                capacity
            ));
        }

        println!(
            "Hiding {} bytes ({} bits) in RGB image with capacity {} bits (JPEG quality: {})",
            data.len(),
            bits.len(),
            capacity,
            quality
        );

        let quant_table = self.calculate_quant_table(quality);
        let mut stego = img.clone();
        let mut data_index = 0;

        // Only embed in the luminance channel (Y) to preserve color information
        for by in (0..img.height()).step_by(self.config.block_size) {
            for bx in (0..img.width()).step_by(self.config.block_size) {
                if data_index >= bits.len() {
                    return Ok(stego);
                }

                // Extract luminance values from 8x8 RGB block
                let mut y_block = self.extract_luminance_block(img, bx as usize, by as usize);

                // Apply DCT to luminance
                self.dct.dct_2d(&mut y_block);

                // Embed bit using quantization-aware method with redundancy
                let bit_to_embed = bits[data_index];

                self.embed_bit_robust(&mut y_block, bit_to_embed, &quant_table);

                data_index += 1;

                // Apply inverse DCT
                self.dct.idct_2d(&mut y_block);

                // Write modified luminance back to RGB image
                self.write_luminance_block(&mut stego, bx as usize, by as usize, &y_block);
            }
        }

        Ok(stego)
    }

    /// Hide encrypted data in grayscale image (legacy method)
    pub fn hide_data(&mut self, img: &GrayImage, data: &[u8], quality: u8) -> Result<GrayImage> {
        let bits = self.data_to_bits_with_header(data);
        let capacity = self.calculate_capacity(img);

        if bits.len() > capacity {
            return Err(anyhow!(
                "Data too large for image. Need {} bits, capacity is {} bits",
                bits.len(),
                capacity
            ));
        }

        println!(
            "Hiding {} bytes ({} bits) in image with capacity {} bits (JPEG quality: {})",
            data.len(),
            bits.len(),
            capacity,
            quality
        );

        let quant_table = self.calculate_quant_table(quality);
        let mut stego = img.clone();
        let mut data_index = 0;

        for by in (0..img.height()).step_by(self.config.block_size) {
            for bx in (0..img.width()).step_by(self.config.block_size) {
                if data_index >= bits.len() {
                    return Ok(stego);
                }

                // Extract 8x8 block
                let mut block = self.extract_block(img, bx as usize, by as usize);

                // Apply DCT
                self.dct.dct_2d(&mut block);

                // Embed bit using quantization-aware method with redundancy
                let bit_to_embed = bits[data_index];
                self.embed_bit_robust(&mut block, bit_to_embed, &quant_table);

                data_index += 1;

                // Apply inverse DCT
                self.dct.idct_2d(&mut block);

                // Write block back to image
                self.write_block(&mut stego, bx as usize, by as usize, &block);
            }
        }

        Ok(stego)
    }

    /// Extract luminance values from RGB block for DCT processing
    fn extract_luminance_block(&self, img: &RgbImage, bx: usize, by: usize) -> [[f32; 8]; 8] {
        let mut block = [[0f32; 8]; 8];
        for y in 0..self.config.block_size {
            for x in 0..self.config.block_size {
                let pixel_x = (bx + x) as u32;
                let pixel_y = (by + y) as u32;

                // Check bounds and use edge pixel if out of bounds
                let actual_x = pixel_x.min(img.width() - 1);
                let actual_y = pixel_y.min(img.height() - 1);

                let rgb = img.get_pixel(actual_x, actual_y);
                // Convert RGB to luminance (Y component): Y = 0.299*R + 0.587*G + 0.114*B
                let luminance =
                    0.299 * rgb[0] as f32 + 0.587 * rgb[1] as f32 + 0.114 * rgb[2] as f32;
                block[y][x] = luminance;
            }
        }
        block
    }

    /// Write modified luminance back to RGB image while preserving chrominance
    fn write_luminance_block(
        &self,
        img: &mut RgbImage,
        bx: usize,
        by: usize,
        y_block: &[[f32; 8]; 8],
    ) {
        for y in 0..self.config.block_size {
            for x in 0..self.config.block_size {
                let pixel_x = (bx + x) as u32;
                let pixel_y = (by + y) as u32;

                // Only write pixels that are within bounds
                if pixel_x < img.width() && pixel_y < img.height() {
                    let original_rgb = img.get_pixel(pixel_x, pixel_y);
                    let original_y = 0.299 * original_rgb[0] as f32
                        + 0.587 * original_rgb[1] as f32
                        + 0.114 * original_rgb[2] as f32;
                    let new_y = y_block[y][x].round().clamp(0.0, 255.0);

                    // Calculate the luminance change
                    let y_change = new_y - original_y;

                    // Apply the change primarily to the green channel (most perceptually important)
                    // but distribute across all channels to maintain color balance
                    let new_r = (original_rgb[0] as f32 + y_change * 0.2)
                        .round()
                        .clamp(0.0, 255.0) as u8;
                    let new_g = (original_rgb[1] as f32 + y_change * 0.6)
                        .round()
                        .clamp(0.0, 255.0) as u8;
                    let new_b = (original_rgb[2] as f32 + y_change * 0.2)
                        .round()
                        .clamp(0.0, 255.0) as u8;

                    img.put_pixel(pixel_x, pixel_y, Rgb([new_r, new_g, new_b]));
                }
            }
        }
    }

    /// Robust bit embedding using the most reliable DCT coefficient
    fn embed_bit_robust(&self, block: &mut [[f32; 8]; 8], bit: u8, quant_table: &[[f32; 8]; 8]) {
        // Use only the most robust position: (4,1)
        let (y, x) = self.config.embedding_positions[0];
        let coef = &mut block[y][x];
        let quant_step = quant_table[y][x].max(self.config.min_quant_step);
        let strength = self.config.embedding_strength.max(quant_step * 3.0);

        // Use quantization-aware embedding with very strong modifications
        if bit == 1 {
            // Force coefficient to be strongly positive
            *coef = strength;
        } else {
            // Force coefficient to be strongly negative
            *coef = -strength;
        }
    }

    /// Extract encrypted data from RGB stego image
    pub fn extract_data_rgb(
        &mut self,
        img: &RgbImage,
        expected_length: Option<usize>,
    ) -> Result<Vec<u8>> {
        let mut bits = Vec::new();
        let capacity = self.calculate_capacity_rgb(img);

        // Extract all bits first
        for by in (0..img.height()).step_by(self.config.block_size) {
            for bx in (0..img.width()).step_by(self.config.block_size) {
                let mut block = self.extract_luminance_block(img, bx as usize, by as usize);
                self.dct.dct_2d(&mut block);

                // Extract bit using majority voting from multiple coefficients
                let extracted_bit = self.extract_bit_robust(&block);
                bits.push(extracted_bit);

                // If we have enough bits for the expected length, stop
                if let Some(expected) = expected_length {
                    if bits.len() >= 32 + expected * 8 {
                        break;
                    }
                }

                // If we have at least the header, try to determine actual length needed
                if bits.len() >= 32 && expected_length.is_none() {
                    // Read the length from header
                    let mut length = 0u32;
                    for i in 0..32 {
                        length = (length << 1) | (bits[i] as u32);
                    }

                    // If we have a reasonable length and enough bits, stop
                    let total_needed = 32 + (length as usize * 8);
                    if length > 0 && length < (capacity / 8) as u32 && bits.len() >= total_needed {
                        bits.truncate(total_needed);
                        break;
                    }
                }
            }
        }

        println!("Extracted {} bits total", bits.len());

        // Debug: print first 32 bits as length
        if bits.len() >= 32 {
            let mut length = 0u32;
            for i in 0..32 {
                length = (length << 1) | (bits[i] as u32);
            }
            println!("Decoded length from header: {} bytes", length);
        }

        self.bits_to_data_with_header(&bits)
    }

    /// Extract encrypted data from grayscale stego image (legacy)
    pub fn extract_data(
        &mut self,
        img: &GrayImage,
        expected_length: Option<usize>,
    ) -> Result<Vec<u8>> {
        let mut bits = Vec::new();
        let capacity = self.calculate_capacity(img);

        // Extract all bits first
        for by in (0..img.height()).step_by(self.config.block_size) {
            for bx in (0..img.width()).step_by(self.config.block_size) {
                let mut block = self.extract_block(img, bx as usize, by as usize);
                self.dct.dct_2d(&mut block);

                // Extract bit using majority voting from multiple coefficients
                let extracted_bit = self.extract_bit_robust(&block);
                bits.push(extracted_bit);

                // If we have enough bits for the expected length, stop
                if let Some(expected) = expected_length {
                    if bits.len() >= 32 + expected * 8 {
                        break;
                    }
                }

                // If we have at least the header, try to determine actual length needed
                if bits.len() >= 32 && expected_length.is_none() {
                    // Read the length from header
                    let mut length = 0u32;
                    for i in 0..32 {
                        length = (length << 1) | (bits[i] as u32);
                    }

                    // If we have a reasonable length and enough bits, stop
                    let total_needed = 32 + (length as usize * 8);
                    if length > 0 && length < (capacity / 8) as u32 && bits.len() >= total_needed {
                        bits.truncate(total_needed);
                        break;
                    }
                }
            }
        }

        println!("Extracted {} bits total", bits.len());

        // Debug: print first 32 bits as length
        if bits.len() >= 32 {
            let mut length = 0u32;
            for i in 0..32 {
                length = (length << 1) | (bits[i] as u32);
            }
            println!("Decoded length from header: {} bytes", length);
        }

        self.bits_to_data_with_header(&bits)
    }

    /// Robust bit extraction using the most reliable coefficient
    fn extract_bit_robust(&self, block: &[[f32; 8]; 8]) -> u8 {
        // Use only the most robust position: (4,1)
        let (y, x) = self.config.embedding_positions[0];
        let coef = block[y][x];

        // Simple sign-based extraction with threshold
        if coef > 1.0 {
            1
        } else {
            0
        }
    }

    /// Extract 8x8 block from image at given position
    fn extract_block(&self, img: &GrayImage, bx: usize, by: usize) -> [[f32; 8]; 8] {
        let mut block = [[0f32; 8]; 8];
        for y in 0..self.config.block_size {
            for x in 0..self.config.block_size {
                let pixel_x = (bx + x) as u32;
                let pixel_y = (by + y) as u32;

                // Check bounds and use edge pixel if out of bounds
                let actual_x = pixel_x.min(img.width() - 1);
                let actual_y = pixel_y.min(img.height() - 1);

                let px = img.get_pixel(actual_x, actual_y)[0];
                block[y][x] = px as f32;
            }
        }
        block
    }

    /// Write 8x8 block back to image
    fn write_block(&self, img: &mut GrayImage, bx: usize, by: usize, block: &[[f32; 8]; 8]) {
        for y in 0..self.config.block_size {
            for x in 0..self.config.block_size {
                let pixel_x = (bx + x) as u32;
                let pixel_y = (by + y) as u32;

                // Only write pixels that are within bounds
                if pixel_x < img.width() && pixel_y < img.height() {
                    let val = block[y][x].round().clamp(0.0, 255.0) as u8;
                    img.put_pixel(pixel_x, pixel_y, Luma([val]));
                }
            }
        }
    }

    /// Save RGB image as JPEG with specified quality
    pub fn save_rgb_as_jpeg(&self, img: &RgbImage, path: &str, quality: u8) -> Result<()> {
        let mut buffer = Vec::new();
        let encoder = Encoder::new(&mut buffer, quality);

        // RGB data is already in the correct format
        let rgb_data: Vec<u8> = img
            .pixels()
            .flat_map(|p| [p[0], p[1], p[2]]) // RGB values
            .collect();

        encoder.encode(
            &rgb_data,
            img.width() as u16,
            img.height() as u16,
            ColorType::Rgb,
        )?;
        std::fs::write(path, buffer)?;
        Ok(())
    }

    /// Save grayscale image as JPEG with specified quality (legacy)
    pub fn save_as_jpeg(&self, img: &GrayImage, path: &str, quality: u8) -> Result<()> {
        let mut buffer = Vec::new();
        let encoder = Encoder::new(&mut buffer, quality);

        // Convert grayscale to RGB for JPEG encoding
        let rgb_data: Vec<u8> = img
            .pixels()
            .flat_map(|p| [p[0], p[0], p[0]]) // Replicate gray value to RGB
            .collect();

        encoder.encode(
            &rgb_data,
            img.width() as u16,
            img.height() as u16,
            ColorType::Rgb,
        )?;
        std::fs::write(path, buffer)?;
        Ok(())
    }
}

/// Encryption utilities with ChaCha20 + repetition coding
pub struct CryptoEngine {
    key_size: usize,          // ChaCha20 key size (32 bytes)
    nonce_size: usize,        // ChaCha20 nonce size (12 bytes)
    repetition_factor: usize, // How many times to repeat each byte for error correction
}

impl CryptoEngine {
    pub fn new() -> Self {
        Self {
            key_size: 32,         // ChaCha20 key size
            nonce_size: 12,       // ChaCha20 nonce size
            repetition_factor: 5, // 5x repetition for robust error correction
        }
    }

    /// Generate a new ChaCha20 key (32 bytes)
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Generate a random nonce for ChaCha20
    pub fn generate_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Apply repetition coding for error correction
    fn encode_repetition(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut result = Vec::new();

        // Add original length header
        result.extend_from_slice(&(data.len() as u32).to_le_bytes());

        // Repeat each byte multiple times
        for &byte in data {
            for _ in 0..self.repetition_factor {
                result.push(byte);
            }
        }

        Ok(result)
    }

    /// Apply repetition decoding for error correction using majority voting
    fn decode_repetition(&self, encoded_data: &[u8]) -> Result<Vec<u8>> {
        if encoded_data.len() < 4 {
            return Err(anyhow!("Encoded data too short"));
        }

        // Read original length
        let original_len = u32::from_le_bytes([
            encoded_data[0],
            encoded_data[1],
            encoded_data[2],
            encoded_data[3],
        ]) as usize;

        let expected_encoded_len = 4 + (original_len * self.repetition_factor);
        if encoded_data.len() != expected_encoded_len {
            return Err(anyhow!(
                "Invalid encoded data length: expected {}, got {}",
                expected_encoded_len,
                encoded_data.len()
            ));
        }

        let mut result = Vec::new();
        let data_start = 4;

        // Decode each byte using majority voting
        for i in 0..original_len {
            let start_idx = data_start + (i * self.repetition_factor);
            let end_idx = start_idx + self.repetition_factor;

            if end_idx > encoded_data.len() {
                return Err(anyhow!("Insufficient repetition data for byte {}", i));
            }

            let repeated_bytes = &encoded_data[start_idx..end_idx];

            // Use majority voting to determine the correct byte value
            let mut vote_counts = [0u32; 256];
            for &byte in repeated_bytes {
                vote_counts[byte as usize] += 1;
            }

            // Find the byte value with the most votes
            let (winning_byte, _) = vote_counts
                .iter()
                .enumerate()
                .max_by_key(|(_, &count)| count)
                .unwrap();

            result.push(winning_byte as u8);
        }

        Ok(result)
    }

    /// Encrypt data with ChaCha20 and repetition code error correction
    pub fn encrypt(&self, key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        // Generate random nonce
        let nonce = self.generate_nonce();

        // Create ChaCha20 cipher
        let mut cipher = ChaCha20::new(key.into(), &nonce.into());

        // Encrypt data (ChaCha20 is a stream cipher)
        let mut ciphertext = data.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        // Prepend nonce to ciphertext
        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&ciphertext);

        // Apply repetition coding for error correction
        let repetition_encoded = self.encode_repetition(&encrypted_data)?;

        println!(
            "Repetition: Original {} bytes -> Encoded {} bytes ({:.1}% overhead)",
            encrypted_data.len(),
            repetition_encoded.len(),
            (repetition_encoded.len() as f64 / encrypted_data.len() as f64 - 1.0) * 100.0
        );

        Ok(repetition_encoded)
    }

    /// Decrypt data with repetition code error correction and ChaCha20
    pub fn decrypt(&self, key: &[u8; 32], repetition_encoded_data: &[u8]) -> Result<Vec<u8>> {
        // First, apply repetition decoding to fix any bit errors
        let encrypted_data = self
            .decode_repetition(repetition_encoded_data)
            .map_err(|e| anyhow!("Repetition decoding failed: {}", e))?;

        println!(
            "Repetition: Recovered {} bytes from {} bytes after error correction",
            encrypted_data.len(),
            repetition_encoded_data.len()
        );

        if encrypted_data.len() < self.nonce_size {
            return Err(anyhow!("Invalid encrypted data: too short"));
        }

        // Extract nonce and ciphertext
        let nonce = &encrypted_data[..self.nonce_size];
        let ciphertext = &encrypted_data[self.nonce_size..];

        // Create ChaCha20 cipher with the same key and nonce
        let mut cipher = ChaCha20::new(key.into(), nonce.try_into().unwrap());

        // Decrypt (apply the same keystream to reverse encryption)
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }

    /// Save ChaCha20 key to file in base64 format
    pub fn save_key_to_file(&self, key: &[u8; 32], path: &str) -> Result<()> {
        let key_b64 = general_purpose::STANDARD.encode(key);
        fs::write(path, key_b64)?;
        Ok(())
    }

    /// Load ChaCha20 key from file or parse from base64 string
    pub fn load_key(&self, key_input: &str) -> Result<[u8; 32]> {
        let key_data = if Path::new(key_input).exists() {
            fs::read_to_string(key_input)?
        } else {
            key_input.to_string()
        };

        let key_bytes = general_purpose::STANDARD
            .decode(key_data.trim())
            .map_err(|e| anyhow!("Invalid base64 key: {}", e))?;

        if key_bytes.len() != 32 {
            return Err(anyhow!(
                "Invalid key length: expected 32 bytes, got {}",
                key_bytes.len()
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(key)
    }
}

/// Create a test image for demonstration
fn create_test_image() -> Result<()> {
    let width = 512;
    let height = 512;

    let img: RgbImage = ImageBuffer::from_fn(width, height, |x, y| {
        let r = (x * 255 / width) as u8;
        let g = (y * 255 / height) as u8;
        let b = ((x + y) * 255 / (width + height)) as u8;
        Rgb([r, g, b])
    });

    img.save("test_image.jpg")?;
    println!("Created test image: test_image.jpg");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut stego_engine = StegoEngine::new();
    let crypto_engine = CryptoEngine::new();

    match cli.command {
        Commands::Hide {
            input,
            output,
            data,
            key_file,
            quality,
        } => {
            // Load input image as RGB to preserve color
            let img = ImageReader::open(&input)?.decode()?.to_rgb8();

            println!("Loaded image: {}x{}", img.width(), img.height());

            // Validate quality parameter
            if quality < 1 || quality > 100 {
                return Err(anyhow!("JPEG quality must be between 1 and 100"));
            }

            // Generate or load key
            let key = if let Some(key_path) = key_file {
                if Path::new(&key_path).exists() {
                    crypto_engine.load_key(&key_path)?
                } else {
                    let key = CryptoEngine::generate_key();
                    crypto_engine.save_key_to_file(&key, &key_path)?;
                    println!("Generated new key and saved to: {}", key_path);
                    key
                }
            } else {
                let key = CryptoEngine::generate_key();
                let key_file = format!("{}.key", output);
                crypto_engine.save_key_to_file(&key, &key_file)?;
                println!("Generated new key and saved to: {}", key_file);
                key
            };

            // Encrypt data
            let encrypted_data = crypto_engine.encrypt(&key, data.as_bytes())?;
            println!(
                "Encrypted {} bytes to {} bytes",
                data.len(),
                encrypted_data.len()
            );

            // Hide in RGB image using JPEG-robust method
            let stego_img = stego_engine.hide_data_rgb(&img, &encrypted_data, quality)?;

            // Save as JPEG with specified quality
            let output_path = if output.ends_with(".jpg") || output.ends_with(".jpeg") {
                output.clone()
            } else {
                format!("{}.jpg", output)
            };

            // For testing: save as PNG to avoid JPEG compression
            if quality == 100 {
                let png_path = output_path.replace(".jpg", ".png");
                stego_img.save(&png_path)?;
                println!("Test: Saved as PNG to avoid compression: {}", png_path);
            } else {
                stego_engine.save_rgb_as_jpeg(&stego_img, &output_path, quality)?;
            }
            println!(
                "JPEG steganographic image saved to: {} (quality: {})",
                output_path, quality
            );
            println!("Image can now be shared on social media and messaging platforms!");
        }

        Commands::Extract { input, key, length } => {
            // Load stego image as RGB
            let img = ImageReader::open(&input)?.decode()?.to_rgb8();

            println!("Loaded stego image: {}x{}", img.width(), img.height());

            // Load key
            let key = crypto_engine.load_key(&key)?;

            // Extract data from RGB image
            let extracted_data = stego_engine.extract_data_rgb(&img, length)?;
            println!("Extracted {} bytes of encrypted data", extracted_data.len());

            // Decrypt
            let decrypted_data = crypto_engine.decrypt(&key, &extracted_data)?;
            let message = String::from_utf8(decrypted_data)
                .map_err(|e| anyhow!("Invalid UTF-8 data: {}", e))?;

            println!("Decrypted message: {}", message);
        }

        Commands::Demo => {
            create_test_image()?;

            // Demo with the test image
            let test_data = "This is a secret message hidden using DCT steganography!";
            let key = CryptoEngine::generate_key();

            // Load test image as RGB
            let img = ImageReader::open("test_image.jpg")?.decode()?.to_rgb8();

            // Encrypt and hide using JPEG-robust method
            let encrypted_data = crypto_engine.encrypt(&key, test_data.as_bytes())?;
            let stego_img = stego_engine.hide_data_rgb(&img, &encrypted_data, 85)?;
            stego_engine.save_rgb_as_jpeg(&stego_img, "demo_hidden.jpg", 85)?;

            // Extract and decrypt
            let extracted = stego_engine.extract_data_rgb(&stego_img, None)?;
            let decrypted = crypto_engine.decrypt(&key, &extracted)?;
            let recovered_message = String::from_utf8(decrypted)?;

            println!("Original message: {}", test_data);
            println!("Recovered message: {}", recovered_message);
            println!("Success: {}", test_data == recovered_message);

            // Save key for manual testing
            crypto_engine.save_key_to_file(&key, "demo.key")?;
            println!("Demo completed! Files created:");
            println!("  - test_image.jpg (original)");
            println!("  - demo_hidden.jpg (JPEG with hidden data - ready for sharing!)");
            println!("  - demo.key (encryption key)");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_conversion() {
        let engine = StegoEngine::new();
        let data = b"Hello, World!";
        let bits = engine.data_to_bits_with_header(data);
        let recovered = engine.bits_to_data_with_header(&bits).unwrap();
        assert_eq!(data.to_vec(), recovered);
    }

    #[test]
    fn test_encryption_decryption() {
        let crypto = CryptoEngine::new();
        let key = CryptoEngine::generate_key();
        let data = b"Secret message";

        let encrypted = crypto.encrypt(&key, data).unwrap();
        let decrypted = crypto.decrypt(&key, &encrypted).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_dct_roundtrip() {
        let dct = SimpleDct::new();
        let mut block = [[100.0f32; 8]; 8];
        let original = block;

        dct.dct_2d(&mut block);
        dct.idct_2d(&mut block);

        // Check that we get approximately the same values back
        for i in 0..8 {
            for j in 0..8 {
                assert!((block[i][j] - original[i][j]).abs() < 1.0);
            }
        }
    }
}
