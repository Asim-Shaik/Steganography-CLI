use crate::error::Result;

/// Discrete Cosine Transform processor for 8x8 image blocks
pub struct DctProcessor {
    cosine_lookup_table: [[f32; 8]; 8],
}

impl DctProcessor {
    /// Creates a new DCT processor with precomputed cosine values
    pub fn new() -> Self {
        let mut cosine_lookup_table = [[0f32; 8]; 8];

        // Precompute cosine values for 8x8 DCT to optimize performance
        for frequency_index in 0..8 {
            for spatial_index in 0..8 {
                cosine_lookup_table[frequency_index][spatial_index] = ((2 * spatial_index + 1)
                    as f32
                    * frequency_index as f32
                    * std::f32::consts::PI
                    / 16.0)
                    .cos();
            }
        }

        Self {
            cosine_lookup_table,
        }
    }

    /// Applies 1D DCT transformation to a single row or column
    fn apply_dct_1d(&self, input_values: &[f32; 8]) -> [f32; 8] {
        let mut output_coefficients = [0f32; 8];

        for frequency_index in 0..8 {
            // DC coefficient normalization factor
            let normalization_factor = if frequency_index == 0 {
                1.0 / (2.0_f32).sqrt()
            } else {
                1.0
            };

            let mut coefficient_sum = 0.0;
            for spatial_index in 0..8 {
                coefficient_sum += input_values[spatial_index]
                    * self.cosine_lookup_table[frequency_index][spatial_index];
            }

            output_coefficients[frequency_index] = 0.5 * normalization_factor * coefficient_sum;
        }

        output_coefficients
    }

    /// Applies 1D inverse DCT transformation to convert back to spatial domain
    fn apply_inverse_dct_1d(&self, input_coefficients: &[f32; 8]) -> [f32; 8] {
        let mut output_values = [0f32; 8];

        for spatial_index in 0..8 {
            let mut pixel_sum = 0.0;

            for frequency_index in 0..8 {
                // DC coefficient normalization factor
                let normalization_factor = if frequency_index == 0 {
                    1.0 / (2.0_f32).sqrt()
                } else {
                    1.0
                };

                pixel_sum += normalization_factor
                    * input_coefficients[frequency_index]
                    * self.cosine_lookup_table[frequency_index][spatial_index];
            }

            output_values[spatial_index] = 0.5 * pixel_sum;
        }

        output_values
    }

    /// Applies 2D DCT to an 8x8 image block
    pub fn apply_forward_dct(&self, image_block: &mut [[f32; 8]; 8]) -> Result<()> {
        // Apply 1D DCT to each row first
        for row in image_block.iter_mut() {
            *row = self.apply_dct_1d(row);
        }

        // Apply 1D DCT to each column
        for column_index in 0..8 {
            let mut column_values = [0f32; 8];
            for row_index in 0..8 {
                column_values[row_index] = image_block[row_index][column_index];
            }
            let dct_column = self.apply_dct_1d(&column_values);
            for row_index in 0..8 {
                image_block[row_index][column_index] = dct_column[row_index];
            }
        }

        Ok(())
    }

    /// Applies 2D inverse DCT to convert DCT coefficients back to pixel values
    pub fn apply_inverse_dct(&self, dct_block: &mut [[f32; 8]; 8]) -> Result<()> {
        // Apply 1D inverse DCT to each column first
        for column_index in 0..8 {
            let mut column_coefficients = [0f32; 8];
            for row_index in 0..8 {
                column_coefficients[row_index] = dct_block[row_index][column_index];
            }
            let spatial_column = self.apply_inverse_dct_1d(&column_coefficients);
            for row_index in 0..8 {
                dct_block[row_index][column_index] = spatial_column[row_index];
            }
        }

        // Apply 1D inverse DCT to each row
        for row in dct_block.iter_mut() {
            *row = self.apply_inverse_dct_1d(row);
        }

        Ok(())
    }
}

impl Default for DctProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dct_roundtrip_accuracy() {
        let dct_processor = DctProcessor::new();
        let mut test_block = [[100.0f32; 8]; 8];
        let original_block = test_block;

        // Apply forward DCT then inverse DCT
        dct_processor.apply_forward_dct(&mut test_block).unwrap();
        dct_processor.apply_inverse_dct(&mut test_block).unwrap();

        // Verify we get approximately the same values back
        for row_index in 0..8 {
            for column_index in 0..8 {
                assert!(
                    (test_block[row_index][column_index] - original_block[row_index][column_index])
                        .abs()
                        < 1.0,
                    "DCT roundtrip failed at position ({}, {})",
                    row_index,
                    column_index
                );
            }
        }
    }
}
