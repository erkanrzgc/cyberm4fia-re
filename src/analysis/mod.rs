//! Analysis module

pub mod functions;
pub mod patterns;
pub mod strings;
pub mod types;

pub use functions::{FunctionDetector, FunctionInfo};
pub use patterns::{PatternMatch, PatternMatcher};
pub use strings::{StringExtractor, StringInfo};
pub use types::{TypeInference, TypeInfo};
