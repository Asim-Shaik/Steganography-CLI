use crate::crypto::CryptographicEngine;
use crate::error::{Result, SteganographyError};
use crate::steganography::SteganographyEngine;
use clap::{Parser, Subcommand};
use image::{io::Reader as ImageReader, ImageBuffer, Rgb, RgbImage};
use std::path::Path;

/// Command-line interface for the steganography tool
#[derive(Parser)]
#[command(name = "steg")]
#[command(about = "A steganography tool for hiding encrypted data in images using DCT")]
#[command(version = "1.0.0")]
pub struct CommandLineInterface {
    #[command(subcommand)]
    pub command: SteganographyCommand,
}

/// Available steganography commands
#[derive(Subcommand)]
pub enum SteganographyCommand {
    /// Hide encrypted data in an image
    Hide {
        /// Input image file path
        #[arg(short, long, help = "Path to the input image file")]
        input: String,
        
        /// Output image file path (without extension)
        #[arg(short, long, help = "Output path for the steganographic image")]
        output: String,
        
        /// Secret data to hide (will be encrypted)
        #[arg(short, long, help = "Secret message to hide in the image")]
        data: String,
        
        /// Optional encryption key file path
        #[arg(short, long, help = "Path to encryption key file (will generate if not provided)")]
        key_file: Option<String>,
        
        /// JPEG quality for output image
        #[arg(
            short, 
            long, 
            default_value = "85",
            help = "JPEG quality (1-100, higher = better quality but larger file)"
        )]
        quality: u8,
    },
    
    /// Extract and decrypt data from a steganographic image
    Extract {
        /// Steganographic image file path
        #[arg(short, long, help = "Path to the steganographic image")]
        input: String,
        
        /// Encryption key (file path or base64 string)
        #[arg(short, long, help = "Encryption key file path or base64 key string")]
        key: String,
        
        /// Expected data length in bytes (optional)
        #[arg(short, long, help = "Expected data length in bytes (optional optimization)")]
        length: Option<usize>,
    },
    
    /// Generate a demonstration with test images
    Demo,
}

/// Command-line interface handler
pub struct CommandLineHandler {
    steganography_engine: SteganographyEngine,
    cryptographic_engine: CryptographicEngine,
}

impl CommandLineHandler {
    /// Creates a new CLI handler with default engines
    pub fn new() -> Self {
        Self {
            steganography_engine: SteganographyEngine::new(),
            cryptographic_engine: CryptographicEngine::new(),
        }
    }

    /// Processes the command-line interface and executes the appropriate command
    pub fn process_command(&mut self, cli: CommandLineInterface) -> Result<()> {
        match cli.command {
            SteganographyCommand::Hide {
                input,
                output,
                data,
                key_file,
                quality,
            } => self.handle_hide_command(input, output, data, key_file, quality),

            SteganographyCommand::Extract { input, key, length } => {
                self.handle_extract_command(input, key, length)
            }

            SteganographyCommand::Demo => self.handle_demo_command(),
        }
    }

    /// Handles the hide command to embed data in an image
    fn handle_hide_command(
        &mut self,
        input_path: String,
        output_path: String,
        secret_data: String,
        key_file_path: Option<String>,
        jpeg_quality: u8,
    ) -> Result<()> {
        // Validate JPEG quality parameter
        if !(1..=100).contains(&jpeg_quality) {
            return Err(SteganographyError::InvalidInput(
                "JPEG quality must be between 1 and 100".to_string(),
            ));
        }

        // Load input image as RGB to preserve color information
        let source_image = ImageReader::open(&input_path)?
            .decode()
            .map_err(|e| SteganographyError::ImageError(e.to_string()))?
            .to_rgb8();

        println!(
            "Loaded source image: {}x{} pixels",
            source_image.width(),
            source_image.height()
        );

        // Generate or load encryption key
        let encryption_key = self.get_or_generate_encryption_key(&output_path, key_file_path)?;

        // Encrypt the secret data with error correction
        let encrypted_data = self
            .cryptographic_engine
            .encrypt_with_error_correction(&encryption_key, secret_data.as_bytes())?;

        println!(
            "Encrypted {} bytes of data to {} bytes",
            secret_data.len(),
            encrypted_data.len()
        );

        // Hide encrypted data in the image
        let steganographic_image = self.steganography_engine.hide_data_in_rgb_image(
            &source_image,
            &encrypted_data,
            jpeg_quality,
        )?;

        // Determine output file path with proper extension
        let output_file_path = self.get_output_file_path(&output_path, jpeg_quality);

        // Save the steganographic image
        self.save_steganographic_image(&steganographic_image, &output_file_path, jpeg_quality)?;

        println!(
            "Steganographic image saved to: {} (quality: {})",
            output_file_path, jpeg_quality
        );
        println!("Image is ready for sharing on social media and messaging platforms!");

        Ok(())
    }

    /// Handles the extract command to retrieve data from a steganographic image
    fn handle_extract_command(
        &mut self,
        input_path: String,
        key_input: String,
        expected_length: Option<usize>,
    ) -> Result<()> {
        // Load steganographic image as RGB
        let steganographic_image = ImageReader::open(&input_path)?
            .decode()
            .map_err(|e| SteganographyError::ImageError(e.to_string()))?
            .to_rgb8();

        println!(
            "Loaded steganographic image: {}x{} pixels",
            steganographic_image.width(),
            steganographic_image.height()
        );

        // Load encryption key
        let encryption_key = self.cryptographic_engine.load_key_from_input(&key_input)?;

        // Extract encrypted data from the image
        let extracted_encrypted_data = self
            .steganography_engine
            .extract_data_from_rgb_image(&steganographic_image, expected_length)?;

        println!(
            "Extracted {} bytes of encrypted data",
            extracted_encrypted_data.len()
        );

        // Decrypt the extracted data
        let decrypted_data = self
            .cryptographic_engine
            .decrypt_with_error_correction(&encryption_key, &extracted_encrypted_data)?;

        let secret_message = String::from_utf8(decrypted_data)?;

        println!("Successfully extracted secret message:");
        println!("\"{}\"", secret_message);

        Ok(())
    }

    /// Handles the demo command to create a demonstration
    fn handle_demo_command(&mut self) -> Result<()> {
        println!("Creating demonstration...");

        // Create a test image
        self.create_demonstration_image()?;

        // Demo parameters
        let demo_message = "Secret message hidden with DCT steganography!";
        let encryption_key = CryptographicEngine::generate_encryption_key();

        // Load the test image
        let test_image = ImageReader::open("demo_test_image.jpg")?
            .decode()
            .map_err(|e| SteganographyError::ImageError(e.to_string()))?
            .to_rgb8();

        // Encrypt and hide the demo message
        let encrypted_data = self
            .cryptographic_engine
            .encrypt_with_error_correction(&encryption_key, demo_message.as_bytes())?;

        let steganographic_image = self.steganography_engine.hide_data_in_rgb_image(
            &test_image,
            &encrypted_data,
            85, // Good quality for demo
        )?;

        // Save the steganographic image
        self.steganography_engine.save_rgb_image_as_jpeg(
            &steganographic_image,
            "demo_hidden_message.jpg",
            85,
        )?;

        // Extract and verify the message
        let extracted_data = self
            .steganography_engine
            .extract_data_from_rgb_image(&steganographic_image, None)?;

        let recovered_data = self
            .cryptographic_engine
            .decrypt_with_error_correction(&encryption_key, &extracted_data)?;

        let recovered_message = String::from_utf8(recovered_data)?;

        // Save encryption key for manual testing
        self.cryptographic_engine
            .save_key_to_file(&encryption_key, "demo_encryption.key")?;

        // Display results
        println!("\n=== DEMONSTRATION RESULTS ===");
        println!("Original message: \"{}\"", demo_message);
        println!("Recovered message: \"{}\"", recovered_message);
        println!("Success: {}", demo_message == recovered_message);

        println!("\n=== FILES CREATED ===");
        println!("📸 demo_test_image.jpg - Original test image");
        println!("🔒 demo_hidden_message.jpg - JPEG with hidden message (ready for sharing!)");
        println!("🔑 demo_encryption.key - Encryption key for manual testing");

        println!("\n=== MANUAL TEST COMMANDS ===");
        println!("Extract message: ./target/release/steg extract -i demo_hidden_message.jpg -k demo_encryption.key");

        Ok(())
    }

    /// Gets or generates an encryption key based on the provided parameters
    fn get_or_generate_encryption_key(
        &self,
        output_path: &str,
        key_file_path: Option<String>,
    ) -> Result<[u8; 32]> {
        match key_file_path {
            Some(key_path) => {
                if Path::new(&key_path).exists() {
                    // Load existing key
                    self.cryptographic_engine.load_key_from_input(&key_path)
                } else {
                    // Generate new key and save to specified path
                    let new_key = CryptographicEngine::generate_encryption_key();
                    self.cryptographic_engine
                        .save_key_to_file(&new_key, &key_path)?;
                    println!("Generated new encryption key and saved to: {}", key_path);
                    Ok(new_key)
                }
            }
            None => {
                // Generate new key and save with output name
                let new_key = CryptographicEngine::generate_encryption_key();
                let auto_key_path = format!("{}.key", output_path);
                self.cryptographic_engine
                    .save_key_to_file(&new_key, &auto_key_path)?;
                println!("Generated new encryption key and saved to: {}", auto_key_path);
                Ok(new_key)
            }
        }
    }

    /// Determines the output file path with appropriate extension
    fn get_output_file_path(&self, output_path: &str, jpeg_quality: u8) -> String {
        if output_path.ends_with(".jpg") || output_path.ends_with(".jpeg") {
            output_path.to_string()
        } else if jpeg_quality == 100 {
            // For testing: save as PNG to avoid compression
            format!("{}.png", output_path)
        } else {
            format!("{}.jpg", output_path)
        }
    }

    /// Saves the steganographic image with appropriate format
    fn save_steganographic_image(
        &self,
        steganographic_image: &RgbImage,
        output_path: &str,
        jpeg_quality: u8,
    ) -> Result<()> {
        if jpeg_quality == 100 && output_path.ends_with(".png") {
            // Save as PNG for testing purposes
            steganographic_image
                .save(output_path)
                .map_err(|e| SteganographyError::ImageError(e.to_string()))?;
            println!("Test mode: Saved as PNG to avoid compression");
        } else {
            // Save as JPEG with specified quality
            self.steganography_engine
                .save_rgb_image_as_jpeg(steganographic_image, output_path, jpeg_quality)?;
        }
        Ok(())
    }

    /// Creates a colorful test image for demonstration
    fn create_demonstration_image(&self) -> Result<()> {
        const IMAGE_WIDTH: u32 = 512;
        const IMAGE_HEIGHT: u32 = 512;

        let test_image: RgbImage = ImageBuffer::from_fn(IMAGE_WIDTH, IMAGE_HEIGHT, |x, y| {
            let red_component = (x * 255 / IMAGE_WIDTH) as u8;
            let green_component = (y * 255 / IMAGE_HEIGHT) as u8;
            let blue_component = ((x + y) * 255 / (IMAGE_WIDTH + IMAGE_HEIGHT)) as u8;
            Rgb([red_component, green_component, blue_component])
        });

        test_image
            .save("demo_test_image.jpg")
            .map_err(|e| SteganographyError::ImageError(e.to_string()))?;

        println!("Created colorful test image: demo_test_image.jpg");
        Ok(())
    }
}

impl Default for CommandLineHandler {
    fn default() -> Self {
        Self::new()
    }
}
