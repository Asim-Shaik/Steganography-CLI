use crate::dct::DctProcessor;
use crate::error::{Result, SteganographyError};
use image::{GrayImage, Luma, Rgb, RgbImage};
use jpeg_encoder::{ColorType, Encoder};

/// Standard JPEG luminance quantization table
const JPEG_LUMINANCE_QUANTIZATION_TABLE: [[f32; 8]; 8] = [
    [16.0, 11.0, 10.0, 16.0, 24.0, 40.0, 51.0, 61.0],
    [12.0, 12.0, 14.0, 19.0, 26.0, 58.0, 60.0, 55.0],
    [14.0, 13.0, 16.0, 24.0, 40.0, 57.0, 69.0, 56.0],
    [14.0, 17.0, 22.0, 29.0, 51.0, 87.0, 80.0, 62.0],
    [18.0, 22.0, 37.0, 56.0, 68.0, 109.0, 103.0, 77.0],
    [24.0, 35.0, 55.0, 64.0, 81.0, 104.0, 113.0, 92.0],
    [49.0, 64.0, 78.0, 87.0, 103.0, 121.0, 120.0, 101.0],
    [72.0, 92.0, 95.0, 98.0, 112.0, 100.0, 103.0, 99.0],
];

/// Configuration for steganography embedding parameters
#[derive(Debug, Clone)]
pub struct EmbeddingConfiguration {
    pub block_size: usize,
    pub embedding_positions: Vec<(usize, usize)>,
    pub embedding_strength: f32,
    pub minimum_quantization_step: f32,
}

impl Default for EmbeddingConfiguration {
    fn default() -> Self {
        Self {
            block_size: 8,
            // Most robust DCT coefficient positions for JPEG compression survival
            embedding_positions: vec![
                (4, 1), // Primary robust position
                (1, 4), // Secondary robust position
                (3, 2), // Backup position
                (2, 3), // Backup position
                (5, 0),
                (0, 5),
                (3, 4),
                (4, 3),
            ],
            embedding_strength: 25.0, // Strong enough to survive JPEG compression
            minimum_quantization_step: 4.0,
        }
    }
}

/// Main steganography engine for hiding and extracting data in images
pub struct SteganographyEngine {
    configuration: EmbeddingConfiguration,
    dct_processor: DctProcessor,
}

impl SteganographyEngine {
    /// Creates a new steganography engine with default configuration
    pub fn new() -> Self {
        Self {
            configuration: EmbeddingConfiguration::default(),
            dct_processor: DctProcessor::new(),
        }
    }

    /// Creates a new steganography engine with custom configuration
    pub fn with_configuration(configuration: EmbeddingConfiguration) -> Self {
        Self {
            configuration,
            dct_processor: DctProcessor::new(),
        }
    }

    /// Converts data to bits with length header for reliable extraction
    fn convert_data_to_bits_with_header(&self, data: &[u8]) -> Vec<u8> {
        let mut bit_stream = Vec::new();

        // Add 32-bit length header for data size information
        let data_length = data.len() as u32;
        for bit_position in (0..32).rev() {
            bit_stream.push(((data_length >> bit_position) & 1) as u8);
        }

        // Convert each byte to its bit representation
        for &data_byte in data {
            for bit_position in (0..8).rev() {
                bit_stream.push(((data_byte >> bit_position) & 1) as u8);
            }
        }

        bit_stream
    }

    /// Converts bits back to data using length header information
    fn convert_bits_to_data_with_header(&self, bit_stream: &[u8]) -> Result<Vec<u8>> {
        if bit_stream.len() < 32 {
            return Err(SteganographyError::InvalidInput(
                "Not enough bits for length header".to_string(),
            ));
        }

        // Extract data length from first 32 bits
        let mut data_length = 0u32;
        for bit_index in 0..32 {
            data_length = (data_length << 1) | (bit_stream[bit_index] as u32);
        }

        let data_bits = &bit_stream[32..];
        let expected_bit_count = data_length as usize * 8;

        if data_bits.len() < expected_bit_count {
            return Err(SteganographyError::InvalidInput(format!(
                "Not enough data bits. Expected {}, got {}",
                expected_bit_count,
                data_bits.len()
            )));
        }

        // Convert bits back to bytes
        let mut recovered_data = Vec::new();
        for bit_chunk in data_bits[..expected_bit_count].chunks(8) {
            let mut byte_value = 0u8;
            for &bit in bit_chunk {
                byte_value = (byte_value << 1) | bit;
            }
            recovered_data.push(byte_value);
        }

        Ok(recovered_data)
    }

    /// Calculates quantization table based on JPEG quality factor
    fn calculate_quantization_table(&self, jpeg_quality: u8) -> [[f32; 8]; 8] {
        let quality_factor = jpeg_quality.clamp(1, 100) as f32;
        let scaling_factor = if quality_factor < 50.0 {
            5000.0 / quality_factor
        } else {
            200.0 - 2.0 * quality_factor
        };

        let mut quantization_table = [[0.0f32; 8]; 8];
        for row_index in 0..8 {
            for column_index in 0..8 {
                let quantized_value =
                    ((JPEG_LUMINANCE_QUANTIZATION_TABLE[row_index][column_index] * scaling_factor
                        + 50.0)
                        / 100.0)
                        .floor()
                        .clamp(1.0, 255.0);
                quantization_table[row_index][column_index] = quantized_value;
            }
        }
        quantization_table
    }

    /// Calculates maximum data capacity for an RGB image in bits
    pub fn calculate_capacity_bits(&self, rgb_image: &RgbImage) -> usize {
        let horizontal_blocks = (rgb_image.width() as usize + self.configuration.block_size - 1)
            / self.configuration.block_size;
        let vertical_blocks = (rgb_image.height() as usize + self.configuration.block_size - 1)
            / self.configuration.block_size;
        horizontal_blocks * vertical_blocks // One bit per block for robustness
    }

    /// Calculates maximum data capacity for a grayscale image in bits (legacy support)
    pub fn calculate_grayscale_capacity_bits(&self, grayscale_image: &GrayImage) -> usize {
        let horizontal_blocks = (grayscale_image.width() as usize + self.configuration.block_size
            - 1)
            / self.configuration.block_size;
        let vertical_blocks = (grayscale_image.height() as usize + self.configuration.block_size
            - 1)
            / self.configuration.block_size;
        horizontal_blocks * vertical_blocks // One bit per block for robustness
    }

    /// Hides encrypted data in RGB image using JPEG-robust DCT steganography
    pub fn hide_data_in_rgb_image(
        &mut self,
        source_image: &RgbImage,
        encrypted_data: &[u8],
        jpeg_quality: u8,
    ) -> Result<RgbImage> {
        let bit_stream = self.convert_data_to_bits_with_header(encrypted_data);
        let available_capacity = self.calculate_capacity_bits(source_image);

        if bit_stream.len() > available_capacity {
            return Err(SteganographyError::CapacityError {
                required: bit_stream.len(),
                available: available_capacity,
            });
        }

        println!(
            "Hiding {} bytes ({} bits) in RGB image with capacity {} bits (JPEG quality: {})",
            encrypted_data.len(),
            bit_stream.len(),
            available_capacity,
            jpeg_quality
        );

        let quantization_table = self.calculate_quantization_table(jpeg_quality);
        let mut steganographic_image = source_image.clone();
        let mut current_bit_index = 0;

        // Embed data in luminance channel only to preserve color information
        for block_y in (0..source_image.height()).step_by(self.configuration.block_size) {
            for block_x in (0..source_image.width()).step_by(self.configuration.block_size) {
                if current_bit_index >= bit_stream.len() {
                    return Ok(steganographic_image);
                }

                // Extract luminance values from RGB block
                let mut luminance_block = self.extract_luminance_block_from_rgb(
                    source_image,
                    block_x as usize,
                    block_y as usize,
                );

                // Apply DCT transformation
                self.dct_processor.apply_forward_dct(&mut luminance_block)?;

                // Embed bit using quantization-aware robust method
                let bit_to_embed = bit_stream[current_bit_index];
                self.embed_bit_robustly(&mut luminance_block, bit_to_embed, &quantization_table);

                current_bit_index += 1;

                // Apply inverse DCT transformation
                self.dct_processor.apply_inverse_dct(&mut luminance_block)?;

                // Write modified luminance back to RGB image
                self.write_luminance_block_to_rgb(
                    &mut steganographic_image,
                    block_x as usize,
                    block_y as usize,
                    &luminance_block,
                );
            }
        }

        Ok(steganographic_image)
    }

    /// Extracts luminance values from RGB block for DCT processing
    fn extract_luminance_block_from_rgb(
        &self,
        rgb_image: &RgbImage,
        block_x: usize,
        block_y: usize,
    ) -> [[f32; 8]; 8] {
        let mut luminance_block = [[0f32; 8]; 8];

        for y in 0..self.configuration.block_size {
            for x in 0..self.configuration.block_size {
                let pixel_x = (block_x + x) as u32;
                let pixel_y = (block_y + y) as u32;

                // Handle boundary conditions by using edge pixels
                let actual_x = pixel_x.min(rgb_image.width() - 1);
                let actual_y = pixel_y.min(rgb_image.height() - 1);

                let rgb_pixel = rgb_image.get_pixel(actual_x, actual_y);
                // Convert RGB to luminance using ITU-R BT.709 standard
                let luminance_value = 0.299 * rgb_pixel[0] as f32
                    + 0.587 * rgb_pixel[1] as f32
                    + 0.114 * rgb_pixel[2] as f32;
                luminance_block[y][x] = luminance_value;
            }
        }
        luminance_block
    }

    /// Writes modified luminance back to RGB image while preserving chrominance
    fn write_luminance_block_to_rgb(
        &self,
        rgb_image: &mut RgbImage,
        block_x: usize,
        block_y: usize,
        luminance_block: &[[f32; 8]; 8],
    ) {
        for y in 0..self.configuration.block_size {
            for x in 0..self.configuration.block_size {
                let pixel_x = (block_x + x) as u32;
                let pixel_y = (block_y + y) as u32;

                // Only modify pixels within image bounds
                if pixel_x < rgb_image.width() && pixel_y < rgb_image.height() {
                    let original_rgb = rgb_image.get_pixel(pixel_x, pixel_y);
                    let original_luminance = 0.299 * original_rgb[0] as f32
                        + 0.587 * original_rgb[1] as f32
                        + 0.114 * original_rgb[2] as f32;
                    let new_luminance = luminance_block[y][x].round().clamp(0.0, 255.0);

                    // Calculate luminance change
                    let luminance_delta = new_luminance - original_luminance;

                    // Distribute luminance change across RGB channels to maintain color balance
                    let new_red = (original_rgb[0] as f32 + luminance_delta * 0.2)
                        .round()
                        .clamp(0.0, 255.0) as u8;
                    let new_green = (original_rgb[1] as f32 + luminance_delta * 0.6)
                        .round()
                        .clamp(0.0, 255.0) as u8;
                    let new_blue = (original_rgb[2] as f32 + luminance_delta * 0.2)
                        .round()
                        .clamp(0.0, 255.0) as u8;

                    rgb_image.put_pixel(pixel_x, pixel_y, Rgb([new_red, new_green, new_blue]));
                }
            }
        }
    }

    /// Embeds a bit robustly using multiple DCT coefficients for redundancy
    fn embed_bit_robustly(
        &self,
        dct_block: &mut [[f32; 8]; 8],
        bit_value: u8,
        quantization_table: &[[f32; 8]; 8],
    ) {
        // Use multiple positions for redundancy (first 4 positions)
        let positions_to_use = &self.configuration.embedding_positions
            [..4.min(self.configuration.embedding_positions.len())];

        for &(coefficient_y, coefficient_x) in positions_to_use {
            let coefficient = &mut dct_block[coefficient_y][coefficient_x];
            let quantization_step = quantization_table[coefficient_y][coefficient_x]
                .max(self.configuration.minimum_quantization_step);
            let embedding_strength = self
                .configuration
                .embedding_strength
                .max(quantization_step * 3.0);

            // Use strong coefficient modification for JPEG compression survival
            if bit_value == 1 {
                *coefficient = embedding_strength; // Strongly positive for bit 1
            } else {
                *coefficient = -embedding_strength; // Strongly negative for bit 0
            }
        }
    }

    /// Extracts encrypted data from RGB steganographic image
    pub fn extract_data_from_rgb_image(
        &mut self,
        steganographic_image: &RgbImage,
        expected_data_length: Option<usize>,
    ) -> Result<Vec<u8>> {
        let mut extracted_bits = Vec::new();
        let total_capacity = self.calculate_capacity_bits(steganographic_image);

        // Extract bits from all blocks
        for block_y in (0..steganographic_image.height()).step_by(self.configuration.block_size) {
            for block_x in (0..steganographic_image.width()).step_by(self.configuration.block_size)
            {
                let mut luminance_block = self.extract_luminance_block_from_rgb(
                    steganographic_image,
                    block_x as usize,
                    block_y as usize,
                );
                self.dct_processor.apply_forward_dct(&mut luminance_block)?;

                // Extract bit using robust method
                let extracted_bit = self.extract_bit_robustly(&luminance_block);
                extracted_bits.push(extracted_bit);

                // Early termination if we have expected length
                if let Some(expected_length) = expected_data_length {
                    if extracted_bits.len() >= 32 + expected_length * 8 {
                        break;
                    }
                }

                // Try to determine actual length from header
                if extracted_bits.len() >= 32 && expected_data_length.is_none() {
                    let mut header_length = 0u32;
                    for bit_index in 0..32 {
                        header_length = (header_length << 1) | (extracted_bits[bit_index] as u32);
                    }

                    let total_bits_needed = 32 + (header_length as usize * 8);
                    if header_length > 0
                        && header_length < (total_capacity / 8) as u32
                        && extracted_bits.len() >= total_bits_needed
                    {
                        extracted_bits.truncate(total_bits_needed);
                        break;
                    }
                }
            }
        }

        println!("Extracted {} bits total", extracted_bits.len());

        self.convert_bits_to_data_with_header(&extracted_bits)
    }

    /// Extracts a bit robustly using majority voting from multiple coefficients
    fn extract_bit_robustly(&self, dct_block: &[[f32; 8]; 8]) -> u8 {
        // Use multiple positions for majority voting to improve reliability
        let positions_to_check = &self.configuration.embedding_positions
            [..4.min(self.configuration.embedding_positions.len())];

        let mut votes_for_1 = 0;
        let mut votes_for_0 = 0;

        for &(coefficient_y, coefficient_x) in positions_to_check {
            let coefficient_value = dct_block[coefficient_y][coefficient_x];

            // Use a more conservative threshold
            if coefficient_value > 10.0 {
                votes_for_1 += 1;
            } else if coefficient_value < -10.0 {
                votes_for_0 += 1;
            }
            // Values between -10 and 10 are considered neutral (no vote)
        }

        // If we have votes, use majority decision
        if votes_for_1 > votes_for_0 {
            1
        } else if votes_for_0 > votes_for_1 {
            0
        } else {
            // If tied or no clear votes, check the primary coefficient with lower threshold
            let (primary_y, primary_x) = self.configuration.embedding_positions[0];
            let primary_value = dct_block[primary_y][primary_x];

            if primary_value > 0.0 {
                1
            } else {
                0
            }
        }
    }

    /// Saves RGB image as JPEG with specified quality
    pub fn save_rgb_image_as_jpeg(
        &self,
        rgb_image: &RgbImage,
        output_path: &str,
        jpeg_quality: u8,
    ) -> Result<()> {
        let mut jpeg_buffer = Vec::new();
        let jpeg_encoder = Encoder::new(&mut jpeg_buffer, jpeg_quality);

        // Convert RGB image to byte array
        let rgb_data: Vec<u8> = rgb_image
            .pixels()
            .flat_map(|pixel| [pixel[0], pixel[1], pixel[2]])
            .collect();

        jpeg_encoder
            .encode(
                &rgb_data,
                rgb_image.width() as u16,
                rgb_image.height() as u16,
                ColorType::Rgb,
            )
            .map_err(|error| SteganographyError::ImageError(error.to_string()))?;

        std::fs::write(output_path, jpeg_buffer)?;
        Ok(())
    }

    // Legacy methods for grayscale image support

    /// Hides data in grayscale image (legacy method)
    pub fn hide_data_in_grayscale_image(
        &mut self,
        source_image: &GrayImage,
        encrypted_data: &[u8],
        jpeg_quality: u8,
    ) -> Result<GrayImage> {
        let bit_stream = self.convert_data_to_bits_with_header(encrypted_data);
        let available_capacity = self.calculate_grayscale_capacity_bits(source_image);

        if bit_stream.len() > available_capacity {
            return Err(SteganographyError::CapacityError {
                required: bit_stream.len(),
                available: available_capacity,
            });
        }

        let quantization_table = self.calculate_quantization_table(jpeg_quality);
        let mut steganographic_image = source_image.clone();
        let mut current_bit_index = 0;

        for block_y in (0..source_image.height()).step_by(self.configuration.block_size) {
            for block_x in (0..source_image.width()).step_by(self.configuration.block_size) {
                if current_bit_index >= bit_stream.len() {
                    return Ok(steganographic_image);
                }

                let mut grayscale_block =
                    self.extract_grayscale_block(source_image, block_x as usize, block_y as usize);

                self.dct_processor.apply_forward_dct(&mut grayscale_block)?;

                let bit_to_embed = bit_stream[current_bit_index];
                self.embed_bit_robustly(&mut grayscale_block, bit_to_embed, &quantization_table);

                current_bit_index += 1;

                self.dct_processor.apply_inverse_dct(&mut grayscale_block)?;

                self.write_grayscale_block(
                    &mut steganographic_image,
                    block_x as usize,
                    block_y as usize,
                    &grayscale_block,
                );
            }
        }

        Ok(steganographic_image)
    }

    /// Extracts 8x8 grayscale block from image
    fn extract_grayscale_block(
        &self,
        grayscale_image: &GrayImage,
        block_x: usize,
        block_y: usize,
    ) -> [[f32; 8]; 8] {
        let mut grayscale_block = [[0f32; 8]; 8];
        for y in 0..self.configuration.block_size {
            for x in 0..self.configuration.block_size {
                let pixel_x = (block_x + x) as u32;
                let pixel_y = (block_y + y) as u32;

                let actual_x = pixel_x.min(grayscale_image.width() - 1);
                let actual_y = pixel_y.min(grayscale_image.height() - 1);

                let pixel_value = grayscale_image.get_pixel(actual_x, actual_y)[0];
                grayscale_block[y][x] = pixel_value as f32;
            }
        }
        grayscale_block
    }

    /// Writes 8x8 grayscale block back to image
    fn write_grayscale_block(
        &self,
        grayscale_image: &mut GrayImage,
        block_x: usize,
        block_y: usize,
        grayscale_block: &[[f32; 8]; 8],
    ) {
        for y in 0..self.configuration.block_size {
            for x in 0..self.configuration.block_size {
                let pixel_x = (block_x + x) as u32;
                let pixel_y = (block_y + y) as u32;

                if pixel_x < grayscale_image.width() && pixel_y < grayscale_image.height() {
                    let pixel_value = grayscale_block[y][x].round().clamp(0.0, 255.0) as u8;
                    grayscale_image.put_pixel(pixel_x, pixel_y, Luma([pixel_value]));
                }
            }
        }
    }

    /// Extracts data from grayscale steganographic image (legacy)
    pub fn extract_data_from_grayscale_image(
        &mut self,
        steganographic_image: &GrayImage,
        expected_data_length: Option<usize>,
    ) -> Result<Vec<u8>> {
        let mut extracted_bits = Vec::new();
        let total_capacity = self.calculate_grayscale_capacity_bits(steganographic_image);

        for block_y in (0..steganographic_image.height()).step_by(self.configuration.block_size) {
            for block_x in (0..steganographic_image.width()).step_by(self.configuration.block_size)
            {
                let mut grayscale_block = self.extract_grayscale_block(
                    steganographic_image,
                    block_x as usize,
                    block_y as usize,
                );
                self.dct_processor.apply_forward_dct(&mut grayscale_block)?;

                let extracted_bit = self.extract_bit_robustly(&grayscale_block);
                extracted_bits.push(extracted_bit);

                if let Some(expected_length) = expected_data_length {
                    if extracted_bits.len() >= 32 + expected_length * 8 {
                        break;
                    }
                }

                if extracted_bits.len() >= 32 && expected_data_length.is_none() {
                    let mut header_length = 0u32;
                    for bit_index in 0..32 {
                        header_length = (header_length << 1) | (extracted_bits[bit_index] as u32);
                    }

                    let total_bits_needed = 32 + (header_length as usize * 8);
                    if header_length > 0
                        && header_length < (total_capacity / 8) as u32
                        && extracted_bits.len() >= total_bits_needed
                    {
                        extracted_bits.truncate(total_bits_needed);
                        break;
                    }
                }
            }
        }

        self.convert_bits_to_data_with_header(&extracted_bits)
    }

    /// Saves grayscale image as JPEG (legacy method)
    pub fn save_grayscale_image_as_jpeg(
        &self,
        grayscale_image: &GrayImage,
        output_path: &str,
        jpeg_quality: u8,
    ) -> Result<()> {
        let mut jpeg_buffer = Vec::new();
        let jpeg_encoder = Encoder::new(&mut jpeg_buffer, jpeg_quality);

        // Convert grayscale to RGB for JPEG encoding
        let rgb_data: Vec<u8> = grayscale_image
            .pixels()
            .flat_map(|pixel| [pixel[0], pixel[0], pixel[0]])
            .collect();

        jpeg_encoder
            .encode(
                &rgb_data,
                grayscale_image.width() as u16,
                grayscale_image.height() as u16,
                ColorType::Rgb,
            )
            .map_err(|error| SteganographyError::ImageError(error.to_string()))?;

        std::fs::write(output_path, jpeg_buffer)?;
        Ok(())
    }
}

impl Default for SteganographyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgb};

    #[test]
    fn test_data_bit_conversion_roundtrip() {
        let stego_engine = SteganographyEngine::new();
        let test_data = b"Hello, World! This is a test message.";
        let bit_stream = stego_engine.convert_data_to_bits_with_header(test_data);
        let recovered_data = stego_engine
            .convert_bits_to_data_with_header(&bit_stream)
            .unwrap();
        assert_eq!(test_data.to_vec(), recovered_data);
    }

    #[test]
    fn test_capacity_calculation() {
        let stego_engine = SteganographyEngine::new();
        let test_image: RgbImage = ImageBuffer::from_fn(64, 64, |_, _| Rgb([128, 128, 128]));
        let capacity = stego_engine.calculate_capacity_bits(&test_image);
        assert_eq!(capacity, 64); // 8x8 blocks = 64 bits capacity
    }
}
