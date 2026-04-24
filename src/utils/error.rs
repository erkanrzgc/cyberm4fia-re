//! Error types for the decompiler

use thiserror::Error;

/// Result type alias for the decompiler
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the decompiler
#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Binary parsing error: {0}")]
    BinaryParse(String),

    #[error("Disassembly error: {0}")]
    Disassembly(String),

    #[error("Analysis error: {0}")]
    Analysis(String),

    #[error("Code generation error: {0}")]
    CodeGeneration(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
