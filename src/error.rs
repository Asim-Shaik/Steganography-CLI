use std::fmt;

/// Custom error type for steganography operations
#[derive(Debug)]
pub enum SteganographyError {
    /// Image processing errors
    ImageError(String),
    /// Encryption/decryption errors
    CryptoError(String),
    /// DCT processing errors
    DctError(String),
    /// Data capacity errors
    CapacityError { required: usize, available: usize },
    /// Invalid input parameters
    InvalidInput(String),
    /// File I/O errors
    IoError(std::io::Error),
    /// Base64 decoding errors
    Base64Error(String),
    /// UTF-8 conversion errors
    Utf8Error(std::string::FromUtf8Error),
}

impl fmt::Display for SteganographyError {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SteganographyError::ImageError(message) => {
                write!(formatter, "Image processing error: {}", message)
            }
            SteganographyError::CryptoError(message) => {
                write!(formatter, "Cryptography error: {}", message)
            }
            SteganographyError::DctError(message) => {
                write!(formatter, "DCT processing error: {}", message)
            }
            SteganographyError::CapacityError {
                required,
                available,
            } => {
                write!(
                    formatter,
                    "Insufficient capacity: need {} bits, only {} available",
                    required, available
                )
            }
            SteganographyError::InvalidInput(message) => {
                write!(formatter, "Invalid input: {}", message)
            }
            SteganographyError::IoError(error) => {
                write!(formatter, "I/O error: {}", error)
            }
            SteganographyError::Base64Error(message) => {
                write!(formatter, "Base64 decoding error: {}", message)
            }
            SteganographyError::Utf8Error(error) => {
                write!(formatter, "UTF-8 conversion error: {}", error)
            }
        }
    }
}

impl std::error::Error for SteganographyError {}

impl From<std::io::Error> for SteganographyError {
    fn from(error: std::io::Error) -> Self {
        SteganographyError::IoError(error)
    }
}

impl From<image::ImageError> for SteganographyError {
    fn from(error: image::ImageError) -> Self {
        SteganographyError::ImageError(error.to_string())
    }
}

impl From<std::string::FromUtf8Error> for SteganographyError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        SteganographyError::Utf8Error(error)
    }
}

impl From<base64::DecodeError> for SteganographyError {
    fn from(error: base64::DecodeError) -> Self {
        SteganographyError::Base64Error(error.to_string())
    }
}

/// Result type alias for steganography operations
pub type Result<T> = std::result::Result<T, SteganographyError>;
