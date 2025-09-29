# 🔐 DCT Steganography with ChaCha20 + Repetition Coding

A robust steganography tool that hides encrypted data in JPEG images using Discrete Cosine Transform (DCT) with ChaCha20 stream cipher and 5x repetition coding for error correction. Designed to survive social media compression and messaging platform processing.

## 🌟 Features

- **🛡️ ChaCha20 Stream Cipher**: Graceful degradation - corrupted bits only affect corresponding plaintext
- **🔄 5x Repetition Coding**: Majority voting error correction survives aggressive JPEG compression
- **🎨 Color Preservation**: Works on luminance channel while preserving chrominance (color)
- **📱 Social Media Ready**: Survives WhatsApp, Instagram, Facebook compression
- **🎯 JPEG Optimized**: Quantization-aware embedding for maximum robustness
- **⚡ High Performance**: Optimized DCT implementation with precomputed cosine tables
- **🔧 CLI Interface**: Easy-to-use command line tool

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd steg

# Build optimized release version
cargo build --release
```

### Basic Usage

```bash
# Hide a message in an image
./target/release/steg hide -i input.jpg -o secret -d "Your secret message" -q 80

# Extract the message
./target/release/steg extract -i secret.jpg -k secret.key

# Run demonstration
./target/release/steg demo
```

## 📖 Detailed Usage

### Hide Command

```bash
./target/release/steg hide [OPTIONS]

Options:
  -i, --input <PATH>      Input image path (JPEG/PNG)
  -o, --output <PATH>     Output image path (will be saved as JPEG)
  -d, --data <TEXT>       Message to hide (will be encrypted)
  -k, --key-file <PATH>   Optional: Use existing key file
  -q, --quality <1-100>   JPEG quality (default: 85)
```

**Examples:**

```bash
# Basic usage with auto-generated key
./target/release/steg hide -i photo.jpg -o hidden -d "Secret message"

# Use specific key file and quality
./target/release/steg hide -i photo.jpg -o hidden -d "Secret message" -k mykey.key -q 90

# Low quality for maximum compression resistance
./target/release/steg hide -i photo.jpg -o hidden -d "Secret message" -q 70
```

### Extract Command

```bash
./target/release/steg extract [OPTIONS]

Options:
  -i, --input <PATH>      Steganographic image path
  -k, --key <PATH|KEY>    Key file path or base64 key string
  -l, --length <BYTES>    Optional: Expected data length
```

**Examples:**

```bash
# Extract using key file
./target/release/steg extract -i hidden.jpg -k hidden.key

# Extract using base64 key string
./target/release/steg extract -i hidden.jpg -k "SGVsbG8gV29ybGQ="
```

### Demo Command

```bash
./target/release/steg demo
```

Creates test files and demonstrates the complete workflow.

## 🔬 Technical Details

### Encryption Stack

1. **ChaCha20 Stream Cipher**

   - 32-byte key, 12-byte nonce
   - Stream cipher provides localized error handling
   - Corrupted bits don't cascade through the message

2. **5x Repetition Coding**

   - Each encrypted byte repeated 5 times
   - Majority voting during decoding
   - ~400% overhead but excellent error correction

3. **DCT Steganography**
   - Embeds in luminance (Y) channel of RGB images
   - Uses middle-frequency coefficients for robustness
   - Quantization-aware embedding strength

### Algorithm Flow

```
Plaintext → ChaCha20 → Repetition Coding → DCT Embedding → JPEG Output
                                                                ↓
Plaintext ← ChaCha20 ← Majority Voting ← DCT Extraction ← JPEG Input
```

### Embedding Positions

The tool uses carefully selected DCT coefficients for maximum robustness:

- Primary: `(4,1)`, `(1,4)` - Most robust positions
- Secondary: `(3,2)`, `(2,3)` - Backup positions
- Additional: `(5,0)`, `(0,5)`, `(3,4)`, `(4,3)`

### Quantization Awareness

- Uses standard JPEG quantization table
- Adapts embedding strength based on quality setting
- Minimum embedding strength of 25.0 for compression survival

## 📊 Performance Characteristics

| Metric                 | Value                    |
| ---------------------- | ------------------------ |
| **Overhead**           | ~400% (5x repetition)    |
| **JPEG Quality Range** | 70-95 (optimal)          |
| **Error Correction**   | Up to 40% bit corruption |
| **Capacity**           | ~0.5 bits per 8x8 block  |
| **Color Preservation** | Full RGB maintained      |

### Capacity Examples

For a 512×512 image:

- Total blocks: 4,096
- Capacity: ~2,048 bits (256 bytes)
- With 5x repetition: ~50 bytes of plaintext

## 🛡️ Security Features

- **ChaCha20**: Industry-standard stream cipher
- **Random Nonces**: Each encryption uses unique nonce
- **Key Management**: Secure base64 key storage
- **Error Resilience**: Graceful degradation under corruption

## 🎯 Use Cases

### Perfect For:

- **Social Media Sharing**: Survives Instagram/Facebook compression
- **Messaging Apps**: Works through WhatsApp image processing
- **Covert Communication**: Natural-looking images
- **Data Backup**: Hidden backup in family photos

### Not Suitable For:

- Large files (capacity limited by repetition overhead)
- Real-time applications (processing intensive)
- Uncompressed storage (unnecessary overhead)

## 🔧 Advanced Configuration

### Quality Settings

- **q=95**: Maximum quality, minimal compression
- **q=85**: Default, good balance
- **q=75**: Standard compression
- **q=70**: Aggressive compression (still works!)

### Customization

The tool uses hardcoded optimal settings, but you can modify:

- `repetition_factor`: Error correction strength
- `embedding_strength`: DCT coefficient modification
- `embedding_positions`: Which coefficients to use

## 📁 File Formats

### Input

- **JPEG** (.jpg, .jpeg)
- **PNG** (.png)
- **Other formats** supported by `image` crate

### Output

- **JPEG only** (optimized for compression survival)
- Automatic `.jpg` extension added if needed

## 🚨 Limitations

1. **Capacity**: Limited by 5x repetition overhead
2. **Processing Time**: DCT operations are CPU intensive
3. **Quality Dependency**: Very low quality (q<70) may cause failures
4. **RGB Only**: Grayscale images converted to RGB

## 🔍 Error Handling

The tool provides detailed error messages for:

- Invalid image formats
- Insufficient image capacity
- Corrupted steganographic data
- Invalid keys or quality settings
- File I/O errors

## 📚 Dependencies

- `chacha20`: Stream cipher implementation
- `image`: Image processing and format support
- `jpeg-encoder`: JPEG encoding with quality control
- `clap`: Command-line argument parsing
- `anyhow`: Error handling
- `base64`: Key encoding/decoding
- `rand`: Cryptographic random number generation
