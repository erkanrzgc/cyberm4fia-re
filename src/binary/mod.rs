//! Binary format parsing module

pub mod elf;
pub mod macho;
pub mod parser;
pub mod pe;

pub use parser::{parse_binary, BinaryFormat, BinaryParser, PeDataDirectoryInfo};
